package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type KeywordFinder interface {
	FindKeywords(string) []string
	Keywords() []string
}

var (
	wordlist          string
	keyword           string
	numThreads        int
	timeout           int
	randomize         bool
	outputFile        string
	prefixesInputFile string
	verbose           bool
)

func parseCommandLineArguments() {
	flag.StringVar(&wordlist, "wordlist", "", "File containing keywords to search in SSL certificates")
	flag.StringVar(&wordlist, "w", "", "File containing keywords to search in SSL certificates (short form)")
	flag.StringVar(&keyword, "keyword", "", "Single keyword to search in SSL certificates")
	flag.IntVar(&numThreads, "threads", 4, "Number of concurrent threads")
	flag.IntVar(&timeout, "timeout", 1, "Timeout in seconds for SSL connection")
	flag.BoolVar(&randomize, "randomize", false, "Randomize the order in which IP addresses are checked")
	flag.StringVar(&outputFile, "output", "", "Output file to save results")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose mode")
	flag.BoolVar(&verbose, "v", false, "Enable verbose mode (short form)")
	flag.StringVar(&prefixesInputFile, "ip-ranges", "", "File containing ip ranges (like a.b.c.d/m)")

	flag.Parse()
}

func main() {
	parseCommandLineArguments()

	if wordlist == "" && keyword == "" {
		fmt.Println("Usage: go run script.go [-wordlist=<your_keywords_file> | -keyword=<your_keyword>] [-threads=<num_threads>] [-timeout=<timeout_seconds>] [-randomize] [-output=<output_file>] [-verbose]")
		return
	}

	var keywordList, prefixes []string
	var err error

	if wordlist != "" {
		keywordList, err = readFileLines(wordlist)
		if err != nil {
			log.Fatalf("Error reading wordlist file: %v", err)
		}
	} else {
		keywordList = []string{keyword}
	}

	if prefixesInputFile != "" {
		prefixes, err = readFileLines(prefixesInputFile)
	} else {
		prefixes, err = getAWSIpRangePrefixes(randomize)
	}
	if err != nil {
		log.Fatal(err)
	}

	checker := newChecker(timeout, NewRegexFinder(keywordList))

	logChan := make(chan string)
	jobChan := make(chan string, numThreads)

	var wg sync.WaitGroup
	wg.Add(numThreads)

	for i := 0; i < numThreads; i++ {
		go func() {
			defer wg.Done()
			for ipRange := range jobChan {
				checker.checkIPRange(ipRange, logChan)
			}
		}()
	}

	go func() {
		for _, prefix := range prefixes {
			jobChan <- prefix
		}
		close(jobChan)
	}()

	go func() {
		wg.Wait()
		close(logChan)
	}()

	var output *os.File
	if outputFile != "" {
		output, err = os.Create(outputFile)
		if err != nil {
			log.Println("Error creating output file:", err)
			return
		}
		defer output.Close()
	}

	for logStr := range logChan {
		fmt.Print(logStr)
		if output != nil {
			_, err := output.WriteString(logStr)
			if err != nil {
				log.Println("Error writing to output file:", err)
			}
		}
	}
}

type cidrChecker struct {
	KeywordFinder
	dialer    *net.Dialer
	tlsConfig *tls.Config
}

func newChecker(timeoutSeconds int, finder KeywordFinder) *cidrChecker {
	return &cidrChecker{
		KeywordFinder: finder,
		dialer:        &net.Dialer{Timeout: time.Duration(timeoutSeconds) * time.Second},
		tlsConfig:     &tls.Config{InsecureSkipVerify: true},
	}
}

func (c *cidrChecker) checkIPRange(ipRange string, logChan chan<- string) {
	_, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return
	}

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		matchedKeywords, err := c.checkSSLKeywords(ip.String())
		if err != nil {
			// TODO: check timeout error
			continue
		}

		if len(matchedKeywords) > 0 {
			if len(matchedKeywords) > 20 {
				logChan <- fmt.Sprintf("Matched keywords found in SSL certificate for IP: %s (Keywords checked: %d)\n", ip.String(), len(matchedKeywords))
			} else {
				logChan <- fmt.Sprintf("Matched keywords found in SSL certificate for IP: %s (Keywords: %s)\n", ip.String(), strings.Join(matchedKeywords, ", "))
			}
		} else if verbose {
			if len(c.Keywords()) > 20 {
				logChan <- fmt.Sprintf("No matched keyword found in SSL certificate for IP: %s (Keywords checked: %d)\n", ip.String(), len(c.Keywords()))
			} else {
				logChan <- fmt.Sprintf("No matched keyword found in SSL certificate for IP: %s (Keywords: %s)\n", ip.String(), strings.Join(c.Keywords(), ", "))
			}
		}
	}
}

func (c *cidrChecker) findCertKeywords(cert *x509.Certificate) []string {
	kws := c.FindKeywords(cert.Subject.CommonName)

	for _, s := range cert.Subject.Organization {
		kws = append(kws, c.FindKeywords(s)...)
	}

	for _, s := range cert.Subject.OrganizationalUnit {
		kws = append(kws, c.FindKeywords(s)...)
	}

	return kws
}

func (c *cidrChecker) checkSSLKeywords(ip string) ([]string, error) {
	conn, err := tls.DialWithDialer(c.dialer, "tcp", ip+":443", c.tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		if res := c.findCertKeywords(cert); len(res) != 0 {
			return res, nil
		}
	}

	return nil, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

type regexFinder struct {
	regexp.Regexp
	keywods []string
}

func NewRegexFinder(kewords []string) *regexFinder {
	reg := regexp.MustCompile(strings.Join(kewords, "|"))
	return &regexFinder{*reg, kewords}
}

func (r *regexFinder) FindKeywords(s string) []string {
	return r.FindAllString(s, 20)
}

func (r *regexFinder) Keywords() []string {
	return r.keywods
}

func getAWSIpRangePrefixes(randomize bool) ([]string, error) {
	type IPRange struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
	}

	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, fmt.Errorf("Error fetching IP ranges: %w", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response body: %w", err)
	}

	var ipRanges IPRange
	err = json.Unmarshal(data, &ipRanges)
	if err != nil {
		return nil, fmt.Errorf("Error parsing JSON: %w", err)
	}

	prefixes := make([]string, len(ipRanges.Prefixes))
	for i, p := range ipRanges.Prefixes {
		prefixes[i] = p.IPPrefix
	}

	if randomize {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(prefixes), func(i, j int) {
			prefixes[i], prefixes[j] = prefixes[j], prefixes[i]
		})
	}

	return prefixes, nil
}

func readFileLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lines := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			lines = append(lines, text)
		}
	}

	if len(lines) == 0 {
		return nil, fmt.Errorf("file '%s' was empty", filePath)
	}
	return lines, scanner.Err()
}
