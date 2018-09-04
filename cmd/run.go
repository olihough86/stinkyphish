// Copyright © 2018 Oliver Hough <hello@oliverhough.cloud>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/idna"

	log "github.com/Sirupsen/logrus"
	homedir "github.com/mitchellh/go-homedir"

	"github.com/olihough86/stinkyphish/lists"

	"github.com/CaliDog/certstream-go"
	"github.com/spf13/cobra"
	"github.com/texttheater/golang-levenshtein/levenshtein"
)

type phish struct {
	domain   string
	words    []string
	udomain  string
	uwords   []string
	IP       string
	score    int
	status   int
	org      string
	wildcard bool
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start monitoring certificate transparency logs for stinky domains",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		stream, errStream := certstream.CertStreamEventStream(true)
		for {
			select {
			case jq := <-stream:
				_, err := jq.String("message_type")

				if err != nil {
					log.Fatal("Error decoding jq string")
				}
				http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
				domains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
				arrlen := len(domains)
				var wg sync.WaitGroup
				wg.Add(arrlen)
				for i := 0; i < arrlen; i++ {
					go func(i int) {
						defer wg.Done()

						phish := newPhish(domains[i])

						// Check domain against whitelists
						if chkWhitelist(phish.domain) {
							return
						}

						// Process wildcard certifcates
						if strings.HasPrefix(phish.domain, "*.") {
							phish.domain = procWildcard(phish.domain, phish.words, &phish.score)
							phish.wildcard = true
						}

						// Process punycode domains
						if phish.udomain != "" {
							procDistance(phish.uwords, &phish.score, 2, 100)
						}

						// Common TLDs used for phishing
						for _, t := range lists.Tlds {
							if strings.HasSuffix(phish.domain, t) {
								phish.score += 25
								break
							}
						}

						// Check against the list of common keywords
						for k, v := range lists.Keywords {
							if strings.Contains(phish.domain, k) {
								phish.score += v
							}
						}

						// Many nested subdomains are a red flag
						if strings.Count(phish.domain, ".") > 3 {
							phish.score += strings.Count(phish.domain, ".") * 3
						}

						// Lots of hyphens are a red flag
						if (strings.Count(phish.domain, "-") > 3 == true) && (strings.Contains(phish.domain, "xn--") == false) {
							phish.score += strings.Count(phish.domain, "-") * 3
						}

						// Check Levenshtein distance
						if phish.udomain == "" {
							procDistance(phish.words, &phish.score, 1, 60)
						}

						// Skip the domain if the score has not reached the baseline
						if phish.score < 90 {
							return
						}

						// Get more infomation for high scoring domains
						if phish.score >= 100 {

							// Get users home dir for logging
							home, _ := homedir.Dir()

							// Resolve the domain to an IP address, skip if it does not resolve.
							IP, err := net.ResolveIPAddr("ip", phish.domain)
							if err != nil {
								return
							}
							phish.IP = IP.IP.String()

							// Lookup IP on ipinfo.io and get the AS name/number
							resp, err := http.Get("https://ipinfo.io/" + phish.IP + "/org")
							if err == nil {
								defer resp.Body.Close()
								if resp.StatusCode == http.StatusOK {
									bodybytes, _ := ioutil.ReadAll(resp.Body)
									bodystring := string(bodybytes)
									phish.org = strings.TrimRight(bodystring, "\n")
								}
							}

							// Make http HEAD request and record the status code
							resp, err = http.Head("https://" + phish.domain)
							if err == nil {
								phish.status = resp.StatusCode
							}

							// Log domain to stinkyphish.txt in users home dir
							f, err := os.OpenFile(home+"/stinkyphish.txt", os.O_APPEND|os.O_WRONLY, 0600)
							if err != nil {
								f, err = os.Create(home + "/stinkyphish.txt")
								if err != nil {
									panic(err)
								}
							}
							defer f.Close()
							if _, err = f.WriteString(phish.domain + "\n"); err != nil {
								panic(err)
							}
							// Score was over 100 so extra info is displayed
							log.WithFields(log.Fields{
								"wildcard": phish.wildcard,
								"score":    phish.score,
								"status":   phish.status,
								"IP":       phish.IP,
								"org":      phish.org,
								"unicode":  phish.udomain,
							}).Warn(phish.domain)
						} else {
							// Score was less than 100 so baic info is displayed
							log.WithFields(log.Fields{
								"wildcard": phish.wildcard,
								"score":    phish.score,
								"status":   phish.status,
								"unicode":  phish.udomain,
							}).Info(phish.domain)
						}
					}(i)
				}
				wg.Wait()
			case err := <-errStream:
				log.Error(err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func newPhish(domain string) phish {
	phish := phish{}
	phish.domain = domain
	phish.udomain = ""
	phish.words = regexp.MustCompile("\\-|\\.").Split(domain, -1)
	phish.score = 0
	phish.wildcard = false
	if strings.Contains(domain, "xn--") {
		p := idna.New()
		phish.udomain, _ = p.ToUnicode(domain)
		phish.uwords = regexp.MustCompile("\\-|\\.").Split(phish.udomain, -1)
	}
	return phish
}

func chkWhitelist(domain string) bool {
	for _, wl := range lists.Whitelist {
		if strings.HasSuffix(domain, wl) {
			return true
		}
	}
	for _, wl := range lists.Prefixes {
		if strings.HasPrefix(domain, wl) {
			return true
		}
	}
	return false
}

func procWildcard(domain string, w []string, s *int) string {
	domain = strings.TrimPrefix(domain, "*.")
	for _, ftld := range lists.Faketlds {
		if w[0] == ftld {
			*s += 10
		}
	}
	return domain
}

func procDistance(w []string, s *int, d int, x int) {
	for key, v := range lists.Keywords {
		if v >= 60 {
			for _, word := range w {
				if levenshtein.DistanceForStrings([]rune(key), []rune(word), levenshtein.DefaultOptions) <= d {
					*s += x
				}
			}
		}
	}
}
