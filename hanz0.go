package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

// JsonReturn holds information about a discovered match.
type JsonReturn struct {
	URL       string `json:"url"`
	Pattern   string `json:"pattern"`
	Match     string `json:"match"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"` // "body" or "header"
}

// HttpResponse holds body and headers from an HTTP request.
type HttpResponse struct {
	Body    string
	Headers http.Header
}

// ANSI color codes for severity.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m" // High
	colorOrange = "\033[33m" // Medium
	colorGreen  = "\033[32m" // Low
	colorCyan   = "\033[36m" // Banner
)

// embeddedPatternsStr includes sensitive patterns.
// filters out short, numeric (port-like) or low-entropy matches to avoid false positives.
var embeddedPatternsStr = `
[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com
[0-9]{9}:[A-Za-z0-9_-]{35}
[0-9a-f]{32}-us[0-9]{1,2}
[0-9a-fA-F]{32}-[0-9a-fA-F]{32}-[0-9a-fA-F]{32}
6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$
(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
AAAA[a-zA-Z0-9_-]{5,100}:[a-zA-Z0-9_-]{140}
AC[a-zA-Z0-9_\-]{32}
(access_key|ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}
(access_token|ACCESS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
Access-Token=[A-Za-z0-9\-_]{100}
access_token=[A-Za-z0-9\-_]{40}
(AC|SK)[A-Za-z0-9]{32}
AIza[0-9A-Za-z\\-_]{35}
AKIA[0-9A-Z]{16}
(amazonaws|AMAZONAWS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
AP[a-zA-Z0-9_\-]{32}
(API|api)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{10}
(apidocs|APIDOCS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(api.googlemapsAIza|API.GOOGLEMAPSAIZA)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(api_key|API_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(apikey|APIKEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
api_key=[A-Za-z0-9]{32}
api[key|_key|\s+]+[a-zA-Z0-9_\-]{7,100}
(api_secret|API_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(apiSecret|APISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"
(app_key|APP_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appkey|APPKEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appkeysecret|APPKEYSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(application_key|APPLICATION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(app_secret|APP_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appsecret|APPSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appspot|APPSPOT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(auth|AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(authorizationToken|AUTHORIZATIONTOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(auth_token|AUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_access|AWS_ACCESS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_access_key_id|AWS_ACCESS_KEY_ID)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_key|AWS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_secret|AWS_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_token|AWS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
[b|B][a|A][s|S][i|I][c|C] [A-Za-z0-9=:_\+\/-]{5,100}
(Basic\s)[A-Za-z0-9\-_=]+:[A-Za-z0-9\-_=]+
bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}
([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)
(bucket_password|BUCKET_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(client_secret|CLIENT_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(cloudfront|CLOUDFRONT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(codecov_token|CODECOV_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(config|CONFIG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(connectionstring|CONNECTIONSTRING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(conn.login|CONN.LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(consumer_key|CONSUMER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(credentials|CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(database_password|DATABASE_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(db_password|DB_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(db_username|DB_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{3}
(dot-files|DOT-FILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(dotfiles|DOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
EAACEdEose0cBA[0-9A-Za-z]+
(encryption_key|ENCRYPTION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$
(fabricApiSecret|FABRICAPISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(fb_secret|FB_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]
firebase=[A-Za-z0-9_-]{40}
(firebase|FIREBASE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(ftp|FTP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(ftp|ftps|http|https)://[A-Za-z0-9-_:\.~]+(@)
ghp_[A-Za-z0-9]{36}
ghr_[A-Za-z0-9]{36}
ghs_[A-Za-z0-9]{36}
(gh_token|GH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
ghu_[A-Za-z0-9]{36}
(GITHUB|github)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{10}
(github_key|GITHUB_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
github_oauth_token=[A-Za-z0-9]{40}
(github_token|GITHUB_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(gitlab|GITLAB)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(gmail_password|GMAIL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(gmail_username|GMAIL_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
google_cloud_api_key=[A-Za-z0-9\-_]{39}
heroku_api_key=[A-Za-z0-9]{32}
(herokuapp|HEROKUAPP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}
https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}
(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}
(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]
(internal|INTERNAL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(irc_pass|IRC_PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}
(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}
(JEKYLL_GITHUB_TOKEN|JEKYLL_GITHUB_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
key-[0-9a-zA-Z]{32}
(key|KEY)(:|=)([0-9A-Za-z\\-]{16,100})
(keyPassword|KEYPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(ldap_password|LDAP_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(ldap_username|LDAP_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(login|LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(mailchimp|MAILCHIMP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(mailgun|MAILGUN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
mailto:[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]{10}
(master_key|MASTER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
mongodb:\/\/[A-Za-z0-9:_@.\-]+
(mydotfiles|MYDOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(mysql|MYSQL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(node_env|NODE_ENV)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(npmrc_auth|NPMRC_AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
oauth_token=[A-Za-z0-9\-_]{36}
(oauth_token|OAUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pass|PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(passwd|PASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(password|PASSWORD)(:|=| : | = )("|')[0-9A-Za-z\\-]{10,100}("|')
(passwords|PASSWORDS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pemprivate|PEMPRIVATE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(preprod|PREPROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(private_key|PRIVATE_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(prod|PROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pwd|PWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pwds|PWDS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
R_[0-9a-f]{32}
(rds.amazonaws.compassword|RDS.AMAZONAWS.COMPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(redis_password|REDIS_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(?:r|s)k_live_[0-9a-zA-Z]{24}
(root_password|ROOT_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(?:r|s)k_live_[0-9a-zA-Z]{24}
s3.amazonaws.com/[a-zA-Z0-9-\.\_]
s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com
s3-[a-zA-Z0-9-\.\_\/]
s3://[a-zA-Z0-9-\.\_]+
secret[_-]?0(=| =|:| :)
	(secret_access_key|SECRET_ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secret_key|SECRET_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secret.password|SECRET.PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(SECRET|secret)(:|=| : | = )("|')[0-9A-Za-z\\-]{10,100}("|')
	(secrets|SECRETS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secret_token|SECRET_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secure|SECURE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(security_credentials|SECURITY_CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(send.keys|SEND.KEYS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(send_keys|SEND_KEYS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(SF_USERNAMEsalesforce|SF_USERNAMESALESFORCE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(sf_username|SF_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
SK[0-9a-fA-F]{32}
sk_live_[0-9a-z]{32}
sk_live_[0-9a-zA-Z]{24}
sk_test_[0-9a-zA-Z]{24}
	(slack_api|SLACK_API)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(slack_token|SLACK_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
sq0csp-[0-9A-Za-z\\-_]{43}
sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}
	(sql_password|SQL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
sqOatp-[0-9A-Za-z\\-_]{22}
sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}
	(ssh2_auth_password|SSH2_AUTH_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(sshpass|SSHPASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(ssh|SSH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(staging|STAGING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(stg|STG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(storePassword|STOREPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(stripe|STRIPE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(swagger|SWAGGER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(testuser|TESTUSER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
token=(?:=|:)(?:\"|')?[0-9A-Za-z\\-]{16,100}(?:\"|')?
TOKEN[\\-|_|A-Z0-9]*(?:'|\")?(?:=|:)(?:'|\")?[\\-|_|A-Z0-9]{10,100}
[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['"\\s][0-9a-zA-Z]{35,44}['"\\s]
virustotal[_-]?apikey(=| =|:| :)
xoxb-[0-9A-Za-z\\-]{50}
xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}
xox[baprs]-([0-9a-zA-Z]{10,48})
xoxp-[0-9A-Za-z\\-]{71}
ya29\\.[0-9A-Za-z\\-_]+
ya29\\.[0-9A-Za-z\\-_]+
`

// classifyPattern labels a regex pattern as "high", "medium", or "low".
func classifyPattern(p string) string {
	pLower := strings.ToLower(p)
	highKeywords := []string{
		"akia", "a3t", "agpa", "aroa", "aida", "aipa", "anpa", "anva", "asia",
		"amzn.mws", "aws_access_key", "aws_secret", "aws_key", "aws_token", "aws_access",
		"hooks.slack.com/services",
		"virustotal", "ghp_", "ghu_", "ghr_", "ghs_",
		"sk_live_", "rk_live_",
		"ya29.", "aiza", "google_cloud_api_key", "googleapi", "api_key", "apikey",
		"private key", "rsa private key", "ssh private key",
		"client_secret", "api_secret", "app_secret", "access_token", "auth_token",
		"secret", "password", "master_key", "authkey", "authorization", "bearer", "token",
		"mongodb://", "mongodb+srv://",
		"heroku_api_key", "firebase", "twilio", "github_oauth_token",
		"prod", "root", "ldap", "administrator", "sysadmin",
		"access_key", "access_key_id", "secret_key", "aws_secret_key", "access_id", "client_id",
	}
	for _, kw := range highKeywords {
		if strings.Contains(pLower, kw) {
			return "high"
		}
	}
	mediumKeywords := []string{
		"xoxb-", "xoxp-", "xoxa-",
		"slack", "github_token", "github_access_token", "github_oauth_token",
		"s3.amazonaws.com", "s3://",
		"mailto:", "basic ", "bearer ", "oauth_token", "api_token", "access-token", "access_token=",
		"sk_test_", "twilio", "sendgrid", "mailgun", "api.googlemaps", "auth_key", "auth_secret",
		"client_secret", "customer_key", "jwt_token", "oauth2_token", "google_auth",
		"ftp", "mysql", "redis", "mongodb", "ssh", "smtp", "postgresql", "sql_password", "database_password",
		"devkey", "dev_secret", "preprod", "stage", "testkey", "test_secret", "testing",
	}
	for _, kw := range mediumKeywords {
		if strings.Contains(pLower, kw) {
			return "medium"
		}
	}
	return "low"
}

// severityToColor returns the ANSI color code based on severity.
func severityToColor(sev string) string {
	switch sev {
	case "high":
		return colorRed
	case "medium":
		return colorOrange
	default:
		return colorGreen
	}
}

// calcShannonEntropy calculates the Shannon entropy of a string.
func calcShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	for _, count := range freq {
		p := count / float64(len(s))
		entropy += -p * math.Log2(p)
	}
	return entropy
}

// isNumeric returns true if the string is composed solely of digits.
func isNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// applies post-match heuristics to filter out false positives.
func getLeak(source, url, data string, compiled []*regexp.Regexp, raw []string, resultsChan chan<- JsonReturn, allowedSeverities map[string]bool, debug bool) {
	now := time.Now().Format(time.RFC3339)
	for i, re := range compiled {
		matches := re.FindAllString(data, -1)
		if len(matches) == 0 {
			continue
		}
		severity := classifyPattern(raw[i])
		if allowedSeverities != nil && len(allowedSeverities) > 0 && !allowedSeverities[severity] {
			continue
		}
		color := severityToColor(severity)
		// Process each match with additional heuristics.
	outer:
		for _, match := range matches {
			// Remove surrounding quotes if any.
			cleaned := strings.Trim(match, "\"'")
			// Enforce a minimum length,tweak if necessary.
			if len(cleaned) < 16 {
				continue outer
			}
			// Skip if the match is purely numeric and within common port range.
			if isNumeric(cleaned) {
				if port, err := strconv.Atoi(cleaned); err == nil && port > 0 && port <= 65535 {
					continue outer
				}
			}
			// Check Shannon entropy; low entropy likely indicates non-random, benign strings.
			if calcShannonEntropy(cleaned) < 3.5 {
				continue outer
			}
			// Skip if the cleaned value is a common placeholder.
			placeholders := []string{"token", "password", "apikey", "key"}
			for _, ph := range placeholders {
				if strings.EqualFold(cleaned, ph) {
					continue outer
				}
			}
			// Report valid leak.
			fmt.Printf(
				"[+] URL: %s\n[+] Source: %s\n[+] Pattern: %s%s%s\n[+] Match: %s%s%s\n\n",
				url, source,
				color, raw[i], colorReset,
				color, cleaned, colorReset,
			)
			resultsChan <- JsonReturn{
				URL:       url,
				Pattern:   raw[i],
				Match:     cleaned,
				Severity:  severity,
				Timestamp: now,
				Source:    source,
			}
		}
	}
}

// readInputFromStdin reads URLs line-by-line from stdin.
func readInputFromStdin(debug bool) []string {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil && debug {
		log.Printf("[DEBUG] Error reading stdin: %v\n", err)
	}
	return urls
}

// loadExternalPatterns loads extra regex patterns from a file.
func loadExternalPatterns(filename string, debug bool) []string {
	var patterns []string
	file, err := os.Open(filename)
	if err != nil {
		if debug {
			log.Printf("[DEBUG] Error opening external patterns file: %v\n", err)
		}
		return patterns
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	if err := scanner.Err(); err != nil && debug {
		log.Printf("[DEBUG] Error reading external patterns file: %v\n", err)
	}
	return patterns
}

// doRequest fetches a URL and returns both its body and headers.
func doRequest(url string, timeout int, userAgent string, debug bool) (HttpResponse, error) {
	var respData HttpResponse
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return respData, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	// Use a context with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return respData, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return respData, err
	}

	respData.Body = string(bodyBytes)
	respData.Headers = resp.Header
	return respData, nil
}

// worker processes URLs from the jobs channel.
func worker(
	wg *sync.WaitGroup,
	jobs <-chan string,
	resultsChan chan<- JsonReturn,
	compiledPatterns []*regexp.Regexp,
	rawPatterns []string,
	verbose bool,
	debug bool,
	timeout int,
	userAgent string,
	allowedSeverities map[string]bool,
	scanHeaders bool,
	completedCount *int64,
) {
	for url := range jobs {
		func(url string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil && debug {
					log.Printf("[DEBUG] Worker recovered from panic for URL %s: %v\n", url, r)
				}
			}()

			if verbose {
				fmt.Printf("[-] Processing: %s\n", url)
			}

			respData, err := doRequest(url, timeout, userAgent, debug)
			if err != nil {
				if debug {
					log.Printf("[DEBUG] Error fetching %s: %v\n", url, err)
				}
				atomic.AddInt64(completedCount, 1)
				return
			}

			// Scan the response body.
			getLeak("body", url, respData.Body, compiledPatterns, rawPatterns, resultsChan, allowedSeverities, debug)

			// Optionally scan the response headers.
			if scanHeaders {
				var headersCombined strings.Builder
				for key, values := range respData.Headers {
					headersCombined.WriteString(key)
					headersCombined.WriteString(": ")
					headersCombined.WriteString(strings.Join(values, ", "))
					headersCombined.WriteString("\n")
				}
				getLeak("header", url, headersCombined.String(), compiledPatterns, rawPatterns, resultsChan, allowedSeverities, debug)
			}

			atomic.AddInt64(completedCount, 1)
		}(url)
	}
}

func main() {
	// Command-line flags.
	verbose := flag.Bool("verbose", false, "Enable verbose mode")
	jsonOutput := flag.String("json", "", "JSON output file")
	timeout := flag.Int("timeout", 5, "Timeout for each request (seconds)")
	threads := flag.Int("threads", 5, "Number of concurrent threads")
	userAgent := flag.String("useragent", "GoLeakScanner/1.0", "User-Agent header for requests")
	severityFilter := flag.String("s", "", "Filter results by severity: 'high', 'medium', or 'low'. For multiple, separate with commas.")
	debug := flag.Bool("debug", false, "Show debug messages")
	stats := flag.Bool("stats", false, "Show periodic scan progress")
	scanHeaders := flag.Bool("scanheaders", false, "Also scan HTTP response headers for leaks")
	externalPatterns := flag.String("patterns", "", "File with additional regex patterns (one per line)")
	typeFilter := flag.String("type", "", "Filter for specific exposures (e.g., mysql, ftp, tokens, redis)")

	flag.Parse()

	fmt.Printf("%sHanz0 by r3dcl1ff@Redflare-Cyber%s\n\n", colorCyan, colorReset)

	// If nothing is piped, show usage.
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Println("[+] Usage: cat urls.txt | ./main [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Process the severity filter.
	var allowedSeverities map[string]bool
	if *severityFilter != "" {
		allowedSeverities = make(map[string]bool)
		for _, sev := range strings.Split(*severityFilter, ",") {
			sev = strings.TrimSpace(strings.ToLower(sev))
			allowedSeverities[sev] = true
		}
	}

	// Build pattern list from the embedded string.
	rawLines := []string{}
	for _, line := range strings.Split(strings.TrimSpace(embeddedPatternsStr), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			rawLines = append(rawLines, trimmed)
		}
	}

	// Load external patterns if provided.
	if *externalPatterns != "" {
		extra := loadExternalPatterns(*externalPatterns, *debug)
		rawLines = append(rawLines, extra...)
	}

	// If a type filter is provided, filter the patterns.
	if *typeFilter != "" {
		var filteredPatterns []string
		keyword := strings.ToLower(*typeFilter)
		// Example: map "tokens" to "token"
		if keyword == "tokens" {
			keyword = "token"
		}
		for _, pat := range rawLines {
			if strings.Contains(strings.ToLower(pat), keyword) {
				filteredPatterns = append(filteredPatterns, pat)
			}
		}
		if len(filteredPatterns) == 0 {
			fmt.Printf("[!] No patterns matched the type filter: %s\n", *typeFilter)
			os.Exit(1)
		}
		rawLines = filteredPatterns
		if *debug {
			log.Printf("[DEBUG] Patterns filtered by type '%s': %d patterns remain\n", *typeFilter, len(rawLines))
		}
	}

	// Pre-compile all patterns.
	var compiledPatterns []*regexp.Regexp
	for _, pattern := range rawLines {
		re, err := regexp.Compile(pattern)
		if err != nil {
			if *debug {
				log.Printf("[DEBUG] Failed to compile pattern (%s): %v\n", pattern, err)
			}
			continue
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	// Read URLs from stdin.
	urls := readInputFromStdin(*debug)
	if len(urls) == 0 {
		if *debug {
			log.Printf("[DEBUG] No input URLs found on stdin.\n")
		} else {
			fmt.Println("[!] No input URLs found on stdin.")
		}
		os.Exit(1)
	}

	// Prepare concurrency.
	jobsChan := make(chan string, len(urls))
	resultsChan := make(chan JsonReturn, len(urls)*2)
	var wg sync.WaitGroup
	var completed int64
	total := int64(len(urls))

	// Show periodic progress if enabled.
	if *stats {
		go func() {
			for {
				done := atomic.LoadInt64(&completed)
				if done >= total {
					fmt.Printf("[STATS] Completed: 100%% (%d/%d)\n", done, total)
					return
				}
				percent := float64(done) / float64(total) * 100
				fmt.Printf("[STATS] Completed: %.2f%% (%d/%d)\n", percent, done, total)
				time.Sleep(1 * time.Second)
			}
		}()
	}

	// Start workers.
	for i := 0; i < *threads; i++ {
		go worker(&wg, jobsChan, resultsChan, compiledPatterns, rawLines, *verbose, *debug, *timeout, *userAgent, allowedSeverities, *scanHeaders, &completed)
	}

	// Enqueue all URLs.
	for _, url := range urls {
		wg.Add(1)
		jobsChan <- url
	}
	close(jobsChan)

	// Wait for workers to finish then close the results channel.
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect all results.
	var allResults []JsonReturn
	for res := range resultsChan {
		allResults = append(allResults, res)
	}

	// If JSON output is requested, save the results.
	if *jsonOutput != "" {
		file, err := os.Create(*jsonOutput)
		if err != nil {
			if *debug {
				log.Printf("[DEBUG] Error creating JSON output file: %v\n", err)
			}
			os.Exit(1)
		}
		defer file.Close()

		encoded, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			if *debug {
				log.Printf("[DEBUG] Error marshaling JSON: %v\n", err)
			}
			os.Exit(1)
		}

		if _, err := file.Write(encoded); err != nil {
			if *debug {
				log.Printf("[DEBUG] Error writing JSON to file: %v\n", err)
			}
			os.Exit(1)
		}
	}
}
