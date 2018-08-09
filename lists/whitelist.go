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

// Whitelist of root domains that are legit
var Whitelist = [...]string{
	".shnpoc.net",
	".microsoft.com",
	".amazonaws.com",
	".skype.net",
	".ally.com",
	".apple.com",
	".netflix.com",
	".myshn.net",
	".netflix.net",
	".composedb.com",
	".google.com",
	".gov.uk",
	".gov",
	".bankofamerica.com",
	".hsbc.com",
	".hsbc.com.hk",
	".hsbc.com.ph",
	".hsbc.com.eg",
	".hsbc.com.mx",
	".googleapis.com",
	".cas.ms",
	".amazonaws.com.cn",
	".appdomain.cloud",
	".amsl.cloud",
	".altemista.cloud",
	".cloud.bmw",
	".oauth.com",
	".ci-cd.com",
	".magentosite.cloud",
	".orckestra.cloud",
	".mybluemix.net",
	".scalecommerce.cloud",
	".dyson.cloud",
}

// Prefixes to exlcude, to avoid many duplicates
var Prefixes = [...]string{
	"cpanel.",
	"webmail.",
	"www.",
	"mail.",
	"webdisk.",
}
