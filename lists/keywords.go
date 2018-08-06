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

package lists

// Keywords to check
var Keywords = map[string]int{
	// Modified list from https://github.com/x0rz/phishing_catcher/blob/master/suspicious.py
	// Generic
	"login":          25,
	"log-in":         25,
	"sign-in":        25,
	"signin":         25,
	"account":        25,
	"verification":   25,
	"verify":         25,
	"webscr":         25,
	"password":       25,
	"credential":     25,
	"support":        25,
	"activity":       25,
	"security":       25,
	"update":         25,
	"authentication": 25,
	"authenticate":   25,
	"authorize":      25,
	"wallet":         25,
	"alert":          25,
	"purchase":       25,
	"transaction":    25,
	"recover":        25,
	"unlock":         25,
	"confirm":        20,
	"live":           15,
	"office":         15,
	"service":        15,
	"manage":         15,
	"invoice":        15,
	"secure":         10,
	"customer":       10,
	"client":         10,
	"bill":           10,
	"online":         10,
	"safe":           10,
	"form":           10,
	"docusign":       50,
	"hmrc":           40,
	"tax":            40,
	"payment":        25,
	"shipping":       25,

	// Apple iCloud
	"appleid": 70,
	"icloud":  60,
	"iforgot": 60,
	"itunes":  50,
	"apple":   30,
	"iphone":  30,
	"ipad":    30,

	// Email
	"outlook":    60,
	"office365":  50,
	"microsoft":  60,
	"windows":    30,
	"protonmail": 70,
	"tutanota":   60,
	"hotmail":    60,
	"gmail":      70,
	"yahoo":      60,
	"google":     60,

	// Social Media
	"twitter":   60,
	"facebook":  60,
	"tumblr":    60,
	"youtube":   40,
	"linkedin":  60,
	"instagram": 60,
	"flickr":    60,
	"whatsapp":  60,
	"snapchat":  60,
	"e-harmony": 60,

	// Cryptocurrency
	"localbitcoin":  70,
	"poloniex":      60,
	"coinhive":      70,
	"bithumb":       60,
	"kraken":        50,
	"bitstamp":      60,
	"bittrex":       60,
	"blockchain":    70,
	"bitflyer":      60,
	"coinbase":      60,
	"hitbtc":        60,
	"lakebtc":       60,
	"bitfinex":      60,
	"bitconnect":    60,
	"coinsbank":     60,
	"ether":         40,
	"myetherwallet": 60,

	// Bank/money
	"paypal":              70,
	"paypalservice":       70,
	"moneygram":           70,
	"westernunion":        70,
	"bankofamerica":       70,
	"wellsfargo":          70,
	"citigroup":           70,
	"santander":           70,
	"morganstanley":       70,
	"barclays":            70,
	"hsbc":                70,
	"scottrade":           70,
	"ameritrade":          70,
	"merilledge":          70,
	"bank":                15,
	"natwest":             70,
	"coop":                25,
	"tsb":                 60,
	"ally.com":            60,
	"jpmorgan":            60,
	"bofa":                25,
	"royalbankofscotland": 70,
	"lloyds":              60,
	"standardchartered":   70,
	"sainsburys":          60,
	"banquepopulaire":     70,
	"bbva":                70,
	"lacaxia":             70,
	"creditsuiss":         70,
	"ingdirect":           70,
	"mufg":                40,
	"jp-bank":             50,
	"mizuhobank":          60,
	"smbc":                40,
	"nochubank":           60,
	"smtb":                40,
	"resonabank":          40,
	"fukuobank":           40,
	"chibabank":           40,
	"tdbank":              40,

	// Ecommerce
	"amazon":    60,
	"overstock": 60,
	//"alibaba":    60, alibaba and aliepress
	//"aliexpress": 60, generate too many false positives
	"leboncoin": 70,

	// Other
	"netflix": 70,
	"skype":   60,
	"github":  60,
	//"uber":           50, Too many false positives
	"lyft":           50,
	"britishairways": 60,
	"easyjet":        60,
	"thompson":       50,
	"jet2":           60,
	"airlines":       40,
	"tesco":          40,
	"asda":           40,
	"dhl":            50,
	"usps":           50,
	"smartsheet":     50,

	// Games
	"worldofwarcraft": 40,
	"blizzard":        40,
	"ubisoft":         40,
	"steam":           40,
	"eveonline":       40,
	"ccp":             40,
	"humblebundle":    40,

	// Miscellaneous & SE tricks
	"cgi-bin": 50,
	".com-":   20,
	"-com.":   20,
	".net-":   20,
	".org-":   20,
	".net.":   20,
	".org.":   20,
	".com.":   20,
	".gov-":   30,
	".gov.":   30,
	".gouv-":  40,
	"-gouv-":  40,
	".gouv.":  40,
}
