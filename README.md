hanz0

hanz0 is a lightweight secret and leak scanner written in Go. It reads URLs from stdin, fetches each URL, and searches for strings that match a set of regular expressions (indicating potential secrets or tokens). It color-codes findings by severity (critical, medium, low) and can optionally save results to a JSON file.



Installation

  

    Clone the Repository:
    git clone https://github.com/your-username/hanz0.git
    cd hanz0go build main.go -o hanz0
    This produces an executable named hanz0.

You need Go installed on your system (version 1.17+ recommended). No additional libraries are required—hanz0 only uses the Go standard library.
Usage
Basic Usage

    Prepare a list of URLs in a text file, one URL per line (e.g., urls.txt).
    
    Pipe the file into hanz0:

    cat urls.txt | ./hanz0

    If nothing is piped in, the tool will display usage/help text.

Flags / Options

    -threads (default 5): Number of concurrent HTTP requests.
    -severity: High,Medium or Low with the -s flag
    -timeout (default 5): HTTP request timeout in seconds.
    -verbose: Prints additional messages, including which URL is currently being scanned.
    -json <filename>: Writes all findings to a JSON file.
    -useragent <ua string> (default GoLeakScanner/1.0): Sets the User-Agent header.

Use -h to see all flags:

    ./hanz0 -h

Examples

Scan URLs with Default Settings:

    cat urls.txt | ./hanz0
    Reads URLs from urls.txt
    Prints secrets found in color-coded format
    No JSON output

Scan Verbosely, 10 Threads, Write JSON:

    cat urls.txt | ./hanz0 -threads 10 -verbose -json results.json

    cat urls.txt | ./hanz0 -useragent "Mozilla/5.0 (compatible; hanz0/1.2)" -timeout 8

Customization

    Patterns: The tool uses an internal list of regex patterns stored in the code. Modify the embeddedPatternsStr and/or the classifyPattern function in main.go to add new patterns or adjust the severity classification.
    Color Output: Adjust the ANSI codes or classification logic in the severityToColor function to change how results are color-coded.
    Logging: The severity and color assignment is a simple demonstration. For more complex risk-based classification, expand the classifyPattern logic.

License

This project is licensed under the terms of the MIT License. See the LICENSE file for details.

Happy hunting! Be sure to use hanz0 only on targets for which you have explicit permission, and comply with all relevant laws and rules.
