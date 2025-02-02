package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// JsonReturn holds information about a discovered match
type JsonReturn struct {
	URL       string `json:"url"`
	Pattern   string `json:"pattern"`
	Match     string `json:"match"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
}
// Add patterns as needed in the future
var embeddedPatternsStr = `
amzn.mws]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}
(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}
virustotal[_-]?apikey(=| =|:| :)
TOKEN[\\-|_|A-Z0-9]*(\'|\")?(:|=)(\'|\")?[\\-|_|A-Z0-9]{10}
xoxb-[0-9A-Za-z\\-]{50}
xoxp-[0-9A-Za-z\\-]{71}
token=[0-9A-Za-z\\-]{5,100}
[0-9a-f]{32}-us[0-9]{1,2}
AIza[0-9A-Za-z\\-_]{35}
AAAA[a-zA-Z0-9_-]{5,100}:[a-zA-Z0-9_-]{140}
(ftp|ftps|http|https)://[A-Za-z0-9-_:\.~]+(@)
(API|api)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{10}
(token|TOKEN)(:|=| : | = )("|')[ 0-9A-Za-z\\-]{10}
(SECRET|secret)(:|=| : | = )("|')[0-9A-Za-z\\-]{10}
(key|KEY)(:|=)[0-9A-Za-z\\-]{10}
secret[_-]?0(=| =|:| :)
(password|PASSWORD)(:|=| : | = )("|')[0-9A-Za-z\\-]{10}
[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com
R_[0-9a-f]{32}
sk_live_[0-9a-z]{32}
access_token,production$[0-9a-z]{161[0-9a,]{32}
key-[0-9a-zA-Z]{32}
xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}
AKIA[0-9A-Z]{16}
basic [a-zA-Z0-9]
bearer [a-zA-Z0-9]
amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
EAACEdEose0cBA[0-9A-Za-z]+
(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}
[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]
(GITHUB|github)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{10}
AIza[0-9A-Za-z\\-_]{35}
(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]
AIza[0-9A-Za-z\\-_]{35}
[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
AIza[0-9A-Za-z\\-_]{35}
ya29\\.[0-9A-Za-z\\-_]+
AIza[0-9A-Za-z\\-_]{35}
key-[0-9a-zA-Z]{32}
# Removed PCRE lookbehind: changed (?<=mailto:) -> mailto:
mailto:[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]{10}
sk_live_[0-9a-z]{32}
xox[baprs]-([0-9a-zA-Z]{10,48})
https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}
(?:r|s)k_live_[0-9a-zA-Z]{24}
sqOatp-[0-9A-Za-z\\-_]{22}
sq0csp-[ 0-9A-Za-z\\-_]{43}
SK[0-9a-fA-F]{32}
(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}
[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]
(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}
AAAA[A-Za-z0-9_-]{5,100}:[A-Za-z0-9_-]{140}
6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$
ya29\.[0-9A-Za-z\-_]+
amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com
[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com
s3://[a-zA-Z0-9-\.\_]+
s3-[a-zA-Z0-9-\.\_\/]
s3.amazonaws.com/[a-zA-Z0-9-\.\_]
basic [a-zA-Z0-9=:_\+\/-]{5,100}
bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}
api[key|_key|\s+]+[a-zA-Z0-9_\-]{7,100}
key-[0-9a-zA-Z]{32}
SK[0-9a-fA-F]{32}
AC[a-zA-Z0-9_\-]{32}
AP[a-zA-Z0-9_\-]{32}
access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}
sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}
sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}
sk_live_[0-9a-zA-Z]{24}
rk_live_[0-9a-zA-Z]{24}
[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*
ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$
\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"
([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)
(JEKYLL_GITHUB_TOKEN|JEKYLL_GITHUB_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(SF_USERNAMEsalesforce|SF_USERNAMESALESFORCE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(access_key|ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(access_token|ACCESS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(amazonaws|AMAZONAWS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(apiSecret|APISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(api_key|API_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(api_secret|API_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(apidocs|APIDOCS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(apikey|APIKEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(app_key|APP_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(app_secret|APP_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appkey|APPKEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appkeysecret|APPKEYSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(application_key|APPLICATION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appsecret|APPSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(appspot|APPSPOT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(auth|AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(auth_token|AUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(authorizationToken|AUTHORIZATIONTOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_access|AWS_ACCESS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_access_key_id|AWS_ACCESS_KEY_ID)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_key|AWS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_secret|AWS_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(aws_token|AWS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(bashrcpassword|BASHRCPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(bucket_password|BUCKET_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(client_secret|CLIENT_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(cloudfront|CLOUDFRONT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(codecov_token|CODECOV_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(config|CONFIG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(conn.login|CONN.LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(connectionstring|CONNECTIONSTRING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(consumer_key|CONSUMER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(credentials|CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(database_password|DATABASE_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(db_password|DB_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(db_username|DB_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{3}
(dot-files|DOT-FILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(dotfiles|DOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(encryption_key|ENCRYPTION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(fabricApiSecret|FABRICAPISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(fb_secret|FB_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(firebase|FIREBASE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(ftp|FTP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(gh_token|GH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(github_key|GITHUB_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(github_token|GITHUB_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(gitlab|GITLAB)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(gmail_password|GMAIL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(gmail_username|GMAIL_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(api.googlemapsAIza|API.GOOGLEMAPSAIZA)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(herokuapp|HEROKUAPP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(internal|INTERNAL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(irc_pass|IRC_PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(key|KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(keyPassword|KEYPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(ldap_password|LDAP_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(ldap_username|LDAP_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(login|LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(mailchimp|MAILCHIMP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(mailgun|MAILGUN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(master_key|MASTER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(mydotfiles|MYDOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(mysql|MYSQL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(node_env|NODE_ENV)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(npmrc_auth|NPMRC_AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(oauth_token|OAUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pass|PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(passwd|PASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(password|PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(passwords|PASSWORDS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pemprivate|PEMPRIVATE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(preprod|PREPROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(private_key|PRIVATE_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(prod|PROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pwd|PWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(pwds|PWDS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(rds.amazonaws.compassword|RDS.AMAZONAWS.COMPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(redis_password|REDIS_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(root_password|ROOT_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	secret|SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secret.password|SECRET.PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secret_access_key|SECRET_ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secret_key|SECRET_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secret_token|SECRET_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secrets|SECRETS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(secure|SECURE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(security_credentials|SECURITY_CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(send.keys|SEND.KEYS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(send_keys|SEND_KEYS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(sf_username|SF_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(slack_api|SLACK_API)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(slack_token|SLACK_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(sql_password|SQL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(ssh|SSH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(ssh2_auth_password|SSH2_AUTH_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(sshpass|SSHPASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(staging|STAGING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(stg|STG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(storePassword|STOREPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(stripe|STRIPE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(swagger|SWAGGER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
	(testuser|TESTUSER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
# GitHub personal access tokens
ghp_[A-Za-z0-9]{36}
ghu_[A-Za-z0-9]{36}
ghr_[A-Za-z0-9]{36}
ghs_[A-Za-z0-9]{36}
`

// ANSI color codes for severity
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m" // Red for high
	colorOrange = "\033[33m" // Orange/yellow for medium
	colorGreen  = "\033[32m" // Green for low
	colorCyan   = "\033[36m" // Cyan for banner
)

// classifyPattern labels a regex pattern as "high", "medium" or "low" severity.
// Any pattern containing highly sensitive keywords (e.g. AWS key prefixes, Google API keys,
// private key markers, "secret", "password", etc.) is marked as high.
// Other tokens (like certain Slack tokens or S3 endpoints) are marked as medium.
func classifyPattern(p string) string {
	pLower := strings.ToLower(p)

	// High severity conditions
	if strings.Contains(pLower, "akia") ||
		strings.Contains(pLower, "a3t") ||
		strings.Contains(pLower, "agpa") ||
		strings.Contains(pLower, "aroa") ||
		strings.Contains(pLower, "aipa") ||
		strings.Contains(pLower, "anpa") ||
		strings.Contains(pLower, "anva") ||
		strings.Contains(pLower, "asia") ||
		strings.Contains(pLower, "amzn.mws") ||
		strings.Contains(pLower, "hooks.slack.com/services") ||
		strings.Contains(pLower, "virustotal") ||
		strings.Contains(pLower, "ghp_") || strings.Contains(pLower, "ghu_") ||
		strings.Contains(pLower, "ghr_") || strings.Contains(pLower, "ghs_") ||
		strings.Contains(pLower, "sk_live_") ||
		strings.Contains(pLower, "ya29.") ||
		strings.Contains(pLower, "aiza") ||
		strings.Contains(pLower, "private key") ||
		strings.Contains(pLower, "client_secret") ||
		strings.Contains(pLower, "api_secret") ||
		strings.Contains(pLower, "api_key") ||
		strings.Contains(pLower, "app_secret") ||
		strings.Contains(pLower, "app_key") ||
		strings.Contains(pLower, "access_token") ||
		strings.Contains(pLower, "secret") ||
		strings.Contains(pLower, "password") {
		return "high"
	}

	// Medium severity conditions
	if strings.Contains(pLower, "xoxb-") ||
		strings.Contains(pLower, "xoxp-") ||
		strings.Contains(pLower, "xoxa-") ||
		strings.Contains(pLower, "slack") ||
		strings.Contains(pLower, "github_token") ||
		strings.Contains(pLower, "rk_live_") ||
		strings.Contains(pLower, "s3.amazonaws.com") ||
		strings.Contains(pLower, "mailto:") ||
		strings.Contains(pLower, "basic ") ||
		strings.Contains(pLower, "bearer ") ||
		strings.Contains(pLower, "oauth_token") {
		return "medium"
	}

	// Default to "low" if no high or medium keywords match.
	return "low"
}

// severityToColor returns the ANSI color code based on the severity classification.
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

// getLeak scans the provided data for matches against all patterns.
func getLeak(url, data string, compiled []*regexp.Regexp, raw []string, resultsChan chan<- JsonReturn, allowedSeverities map[string]bool, debug bool) {
	now := time.Now().Format(time.RFC3339)
	for i, re := range compiled {
		matches := re.FindAllString(data, -1)
		if len(matches) == 0 {
			continue
		}
		// Determine severity
		severity := classifyPattern(raw[i])

		// If a severity filter is provided, skip results that are not in the allowed set.
		if allowedSeverities != nil && len(allowedSeverities) > 0 {
			if !allowedSeverities[severity] {
				continue
			}
		}

		color := severityToColor(severity)

		for _, match := range matches {
			// Color-coded console output.
			fmt.Printf(
				"[+] URL: %s\n[+] Pattern: %s%s%s\n[+] Match: %s%s%s\n\n",
				url,
				color, raw[i], colorReset,
				color, match, colorReset,
			)

			// Send to results channel for JSON collation.
			resultsChan <- JsonReturn{
				URL:       url,
				Pattern:   raw[i],
				Match:     match,
				Severity:  severity,
				Timestamp: now,
			}
		}
	}
}

// readInputFromStdin reads all whitespace-delimited tokens (URLs) from stdin.
func readInputFromStdin(debug bool) []string {
	reader := bufio.NewReader(os.Stdin)
	var output []rune

	for {
		input, _, err := reader.ReadRune()
		if err != nil {
			if err == io.EOF {
				break
			}
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Error reading stdin: %v\n", err)
			}
			break
		}
		output = append(output, input)
	}

	return strings.Fields(string(output))
}

func doRequest(url string, timeout int, userAgent string, debug bool) (string, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

func worker(
	wg *sync.WaitGroup,
	jobs <-chan string,
	resultsChan chan<- JsonReturn,
	cPatterns []*regexp.Regexp,
	rawPatterns []string,
	verbose bool,
	debug bool,
	timeout int,
	userAgent string,
	allowedSeverities map[string]bool,
	completedCount *int64,
) {
	defer func() {
		if r := recover(); r != nil && debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] Worker crashed: %v\n", r)
		}
	}()

	for url := range jobs {
		if verbose {
			fmt.Printf("[-] Looking at: %s\n", url)
		}

		body, err := doRequest(url, timeout, userAgent, debug)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Error fetching %s: %v\n", url, err)
			}
			wg.Done()
			atomic.AddInt64(completedCount, 1)
			continue
		}

		getLeak(url, body, cPatterns, rawPatterns, resultsChan, allowedSeverities, debug)

		wg.Done()
		atomic.AddInt64(completedCount, 1)
	}
}

func main() {
	// Flags
	verbose := flag.Bool("verbose", false, "Enable verbose mode")
	jsonOutput := flag.String("json", "", "JSON output file")
	timeout := flag.Int("timeout", 5, "Timeout for each request (seconds)")
	threads := flag.Int("threads", 5, "Number of concurrent threads")
	userAgent := flag.String("useragent", "GoLeakScanner/1.0", "User-Agent header for requests")
	// The -s flag accepts a comma-separated list of severities.
	severityFilter := flag.String("s", "", "Filter results by severity: 'high', 'medium', or 'low'. For multiple severities, separate with commas (e.g. -s high,medium). Empty for all.")

	// Additional flags:
	debug := flag.Bool("debug", false, "Show debug messages (errors, warnings, etc.)")
	stats := flag.Bool("stats", false, "Show periodic scan progress (percent complete)")

	flag.Parse()

	// Print Redflare banner in cyan
	fmt.Printf("%sHanz0 by Redflare-Cyber%s\n\n", colorCyan, colorReset)

	// If nothing is piped, show usage
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
	rawLines := strings.Split(strings.TrimSpace(embeddedPatternsStr), "\n")

	// Compile all patterns.
	var compiledPatterns []*regexp.Regexp
	for _, pattern := range rawLines {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			if *debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Failed to compile pattern (%s): %v\n", pattern, err)
			}
			continue
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	// Read all URLs from stdin.
	urls := readInputFromStdin(*debug)
	if len(urls) == 0 {
		if *debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] No input URLs found on stdin.\n")
		} else {
			fmt.Println("[!] No input URLs found on stdin.")
		}
		os.Exit(1)
	}

	jobsChan := make(chan string, len(urls))
	resultsChan := make(chan JsonReturn, len(urls)*2) // buffer extra for multiple matches
	var wg sync.WaitGroup

	var completed int64
	total := int64(len(urls))

	// If --stats is enabled, show periodic progress.
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
		go worker(
			&wg,
			jobsChan,
			resultsChan,
			compiledPatterns,
			rawLines,
			*verbose,
			*debug,
			*timeout,
			*userAgent,
			allowedSeverities,
			&completed,
		)
	}

	// Enqueue all URLs.
	for _, url := range urls {
		wg.Add(1)
		jobsChan <- url
	}
	close(jobsChan)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var allResults []JsonReturn
	for res := range resultsChan {
		allResults = append(allResults, res)
	}

	if *jsonOutput != "" {
		file, err := os.Create(*jsonOutput)
		if err != nil {
			if *debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Error creating JSON output file: %v\n", err)
			}
			os.Exit(1)
		}
		defer file.Close()

		encoded, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			if *debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Error marshaling JSON: %v\n", err)
			}
			os.Exit(1)
		}

		if _, err := file.Write(encoded); err != nil {
			if *debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Error writing JSON to file: %v\n", err)
			}
			os.Exit(1)
		}
	}
}
