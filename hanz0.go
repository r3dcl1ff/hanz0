package main

import (
    "bufio"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "regexp"
    "strings"
    "sync"
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

// embeddedPatternsStr includes the original patterns (lightly adapted for Go's regexp engine)
// plus some additional ones. Each pattern is on its own line; we split it at runtime.
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
(db_username|DB_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(dbpasswd|DBPASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(dbpassword|DBPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
(dbuser|DBUSER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{3}
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
(secret|SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
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
    colorRed    = "\033[31m" // "Red" for critical
    colorOrange = "\033[33m" // "Orange"/yellow for medium
    colorGreen  = "\033[32m" // Green for low
)

// classifyPattern is a simple helper to label patterns as "critical", "medium" or "low" severity.
// You can expand/adjust this logic as needed.
func classifyPattern(p string) string {
    pLower := strings.ToLower(p)

    // Example heuristics for demonstration
    switch {
    // "Critical" heuristics
    case strings.Contains(pLower, "akia"),
        strings.Contains(pLower, "aws_secret"), strings.Contains(pLower, "secret_access_key"),
        strings.Contains(pLower, "ghp_"), // GitHub personal tokens
        strings.Contains(pLower, "sk_live_"), // Stripe live keys
        strings.Contains(pLower, "secret key"), strings.Contains(pLower, "secret_token"):
        return "critical"

    // "Medium" heuristics
    case strings.Contains(pLower, "xoxb-"), strings.Contains(pLower, "xoxp-"),
        strings.Contains(pLower, "slack"), strings.Contains(pLower, "github_token"),
        strings.Contains(pLower, "rk_live_"):
        return "medium"
    }
    // Else "low"
    return "low"
}

// severityToColor returns the ANSI color code based on the severity classification
func severityToColor(sev string) string {
    switch sev {
    case "critical":
        return colorRed
    case "medium":
        // There's no pure "orange" in standard ANSI, so we use yellow.
        return colorOrange
    default:
        return colorGreen
    }
}

// getLeak finds *all* non-overlapping matches for each pattern in "data"
func getLeak(url, data string, compiled []*regexp.Regexp, raw []string, resultsChan chan<- JsonReturn) {
    now := time.Now().Format(time.RFC3339)
    for i, re := range compiled {
        matches := re.FindAllString(data, -1)
        if len(matches) == 0 {
            continue
        }
        // Determine severity once per pattern
        severity := classifyPattern(raw[i])
        color := severityToColor(severity)

        for _, match := range matches {
            // Color-coded console output
            fmt.Printf(
                "[+] URL: %s\n[+] Pattern: %s%s%s\n[+] Match: %s%s%s\n\n",
                url,
                color, raw[i], colorReset,
                color, match, colorReset,
            )

            // Send to results channel for JSON collation
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
func readInputFromStdin() []string {
    reader := bufio.NewReader(os.Stdin)
    var output []rune

    for {
        input, _, err := reader.ReadRune()
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Printf("Error reading stdin: %v", err)
            break
        }
        output = append(output, input)
    }

    return strings.Fields(string(output))
}

// doRequest fetches a URL with a configurable timeout and user-agent; returns the response body as string.
func doRequest(url string, timeout int, userAgent string) (string, error) {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired/self-signed SSL
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

// worker runs as a goroutine to process URLs from the jobs channel
func worker(
    wg *sync.WaitGroup,
    jobs <-chan string,
    resultsChan chan<- JsonReturn,
    cPatterns []*regexp.Regexp,
    rawPatterns []string,
    verbose bool,
    timeout int,
    userAgent string,
) {
    defer func() {
        // Handle unexpected panics gracefully
        if r := recover(); r != nil {
            log.Printf("[!] Worker crashed: %v", r)
        }
    }()

    for url := range jobs {
        defer wg.Done()

        if verbose {
            fmt.Printf("[-] Looking at: %s\n", url)
        }
        body, err := doRequest(url, timeout, userAgent)
        if err != nil {
            log.Printf("[!] Error fetching %s: %v", url, err)
            continue
        }
        getLeak(url, body, cPatterns, rawPatterns, resultsChan)
    }
}

func main() {
    // Flags
    verbose := flag.Bool("verbose", false, "Enable verbose mode")
    jsonOutput := flag.String("json", "", "JSON output file")
    timeout := flag.Int("timeout", 5, "Timeout for each request (seconds)")
    threads := flag.Int("threads", 5, "Number of concurrent threads")
    userAgent := flag.String("useragent", "GoLeakScanner/1.0", "User-Agent header for requests")
    flag.Parse()

    // If nothing is piped, show usage
    stat, _ := os.Stdin.Stat()
    if (stat.Mode() & os.ModeCharDevice) != 0 {
        fmt.Println("[+] Usage: cat urls.txt | ./main [options]")
        flag.PrintDefaults()
        os.Exit(1)
    }

    // Build pattern list from the embedded string
    rawLines := strings.Split(strings.TrimSpace(embeddedPatternsStr), "\n")

    // Compile all patterns up-front
    var compiledPatterns []*regexp.Regexp
    for _, pattern := range rawLines {
        // Trim and skip empty lines or comments
        pattern = strings.TrimSpace(pattern)
        if pattern == "" || strings.HasPrefix(pattern, "#") {
            continue
        }
        re, err := regexp.Compile(pattern)
        if err != nil {
            // If a pattern fails to compile, log and skip it
            log.Printf("[!] Failed to compile pattern (%s): %v", pattern, err)
            continue
        }
        compiledPatterns = append(compiledPatterns, re)
    }

    // Read all URLs from stdin
    urls := readInputFromStdin()
    if len(urls) == 0 {
        fmt.Println("[!] No input URLs found on stdin.")
        os.Exit(1)
    }

    // Prepare concurrency
    jobsChan := make(chan string, len(urls))
    resultsChan := make(chan JsonReturn, len(urls)*2) // buffer extra for multiple matches
    var wg sync.WaitGroup

    // Start workers
    for i := 0; i < *threads; i++ {
        go worker(&wg, jobsChan, resultsChan, compiledPatterns, rawLines, *verbose, *timeout, *userAgent)
    }

    // Enqueue all URLs
    for _, url := range urls {
        wg.Add(1)
        jobsChan <- url
    }
    close(jobsChan)

    // Spin up a goroutine to wait until all workers finish, then close results
    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    // Collect all results
    var allResults []JsonReturn
    for res := range resultsChan {
        allResults = append(allResults, res)
    }

    // If JSON output is requested, save the results
    if *jsonOutput != "" {
        file, err := os.Create(*jsonOutput)
        if err != nil {
            log.Fatalf("Error creating JSON output file: %v", err)
        }
        defer file.Close()

        encoded, err := json.MarshalIndent(allResults, "", "  ")
        if err != nil {
            log.Fatalf("Error marshaling JSON: %v", err)
        }

        if _, err := file.Write(encoded); err != nil {
            log.Fatalf("Error writing JSON to file: %v", err)
        }
    }
}
