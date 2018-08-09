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

	"stinkyphish/lists"

	"github.com/CaliDog/certstream-go"
	"github.com/spf13/cobra"
	"github.com/texttheater/golang-levenshtein/levenshtein"
)

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
						score := 0
						status := 0
						iswildcard := false
						org := ""
						words := regexp.MustCompile("\\-|\\.").Split(domains[i], -1)

						// Check domain against whitelists
						if chkWhitelist(domains[i]) {
							return
						}

						// Strip wildcard character *. and check for fake tld
						if strings.HasPrefix(domains[i], "*.") {
							domains[i] = strings.TrimPrefix(domains[i], "*.")
							iswildcard = true
							for _, ftld := range lists.Faketlds {
								if words[0] == ftld {
									score += 10
								}
							}
						}
						// Punycode domains (this is very early Homoglyph detection)
						if strings.Contains(domains[i], "xn--") == true {
							p := idna.New()
							u, _ := p.ToUnicode(domains[i])
							words := regexp.MustCompile("\\-|\\.").Split(u, -1)
							for k, v := range lists.Keywords {
								if v >= 60 {
									for _, w := range words {
										if levenshtein.DistanceForStrings([]rune(k), []rune(w), levenshtein.DefaultOptions) <= 2 {
											score += 100
											log.Warn(u)
										}
									}
								}
							}
						}
						// Dodgy tlds
						for _, t := range lists.Tlds {
							if strings.HasSuffix(domains[i], t) {
								score += 25
								break
							}
						}
						// Keywords
						for k, v := range lists.Keywords {
							if strings.Contains(domains[i], k) {
								score += v
							}
						}
						// Nested Subdomains
						if strings.Count(domains[i], ".") > 3 {
							score += strings.Count(domains[i], ".") * 3
						}
						// Lots of hyphens
						if (strings.Count(domains[i], "-") > 3 == true) && (strings.Contains(domains[i], "xn--") == false) {
							score += strings.Count(domains[i], "-") * 3
						}
						// levenshtein distance for important keywords
						for k, v := range lists.Keywords {
							if v >= 60 {
								for _, w := range words {
									if levenshtein.DistanceForStrings([]rune(k), []rune(w), levenshtein.DefaultOptions) == 1 {
										score += 60
									}
								}
							}
						}
						// TODO optional baseline via --baseline
						if score < 90 {
							return
						}
						// Get more infomation for high scoring domains
						if score >= 100 {
							// Get users home dir for logging
							home, _ := homedir.Dir()
							// Resolve to IP. If domain does not resolve just skip it
							ipaddr, err := net.ResolveIPAddr("ip", domains[i])
							if err != nil {
								return
							}
							// Make http HEAD request and record the status code
							resp, err := http.Head("https://" + domains[i])
							if err == nil {
								status = resp.StatusCode
							}
							// Lookup IP on ipinfo.io and get the AS name/number
							resp, err = http.Get("https://ipinfo.io/" + ipaddr.IP.String() + "/org")
							if err == nil {
								defer resp.Body.Close()
								if resp.StatusCode == http.StatusOK {
									bodybytes, _ := ioutil.ReadAll(resp.Body)
									bodystring := string(bodybytes)
									org = strings.TrimRight(bodystring, "\n")
								}
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
							if _, err = f.WriteString(domains[i] + "\n"); err != nil {
								panic(err)
							}
							// Score was over 100 so extra info is displayed
							log.WithFields(log.Fields{
								"wildcard": iswildcard,
								"score":    score,
								"status":   status,
								"IP":       ipaddr,
								"org":      org,
							}).Warn(domains[i])
						} else {
							// Score was less than 100 so baic info is displayed
							log.WithFields(log.Fields{
								"wildcard": iswildcard,
								"score":    score,
								"status":   status,
							}).Info(domains[i])
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

func chkWhitelist(domain string) bool {
	//Skip whitelist suffix
	for _, wl := range lists.Whitelist {
		if strings.HasSuffix(domain, wl) {
			return true
		}
	}
	//Skip whitelist prefix
	for _, wl := range lists.Prefixes {
		if strings.HasPrefix(domain, wl) {
			return true
		}
	}
	return false
}
