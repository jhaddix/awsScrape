package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type IPRange struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
	} `json:"prefixes"`
}

type checkIPRangeParams struct {
	ipRange     string
	keywordList []string
	timeout     int
	verbose     bool
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

	ipChan := make(chan string)
	jobChan := make(chan checkIPRangeParams, numThreads)

	var wg sync.WaitGroup
	wg.Add(numThreads)

	for i := 0; i < numThreads; i++ {
		go func() {
			defer wg.Done()
			for params := range jobChan {
				checkIPRange(params, ipChan)
			}
		}()
	}

	go func() {
		for _, prefix := range prefixes {
			params := checkIPRangeParams{
				ipRange:     prefix,
				keywordList: keywordList,
				timeout:     timeout,
				verbose:     verbose,
			}
			jobChan <- params
		}
		close(jobChan)
	}()

	go func() {
		wg.Wait()
		close(ipChan)
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

	for ip := range ipChan {
		fmt.Print(ip)
		if output != nil {
			_, err := output.WriteString(ip)
			if err != nil {
				log.Println("Error writing to output file:", err)
			}
		}
	}
}

func checkIPRange(params checkIPRangeParams, ipChan chan<- string) {
	_, ipNet, err := net.ParseCIDR(params.ipRange)
	if err != nil {
		return
	}

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		found := false
		matchedKeywords := []string{}
		for _, keyword := range params.keywordList {
			if checkSSLKeyword(ip.String(), keyword, params.timeout) {
				matchedKeywords = append(matchedKeywords, keyword)
				found = true
			}
		}

		if found {
			if len(matchedKeywords) > 20 {
				ipChan <- fmt.Sprintf("Matched keywords found in SSL certificate for IP: %s (Keywords checked: %d)\n", ip.String(), len(matchedKeywords))
			} else {
				ipChan <- fmt.Sprintf("Matched keywords found in SSL certificate for IP: %s (Keywords: %s)\n", ip.String(), strings.Join(matchedKeywords, ", "))
			}
		} else if params.verbose {
			if len(params.keywordList) > 20 {
				ipChan <- fmt.Sprintf("No matched keyword found in SSL certificate for IP: %s (Keywords checked: %d)\n", ip.String(), len(params.keywordList))
			} else {
				ipChan <- fmt.Sprintf("No matched keyword found in SSL certificate for IP: %s (Keywords: %s)\n", ip.String(), strings.Join(params.keywordList, ", "))
			}
		}
	}
}

func checkSSLKeyword(ip, keyword string, timeout int) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeout) * time.Second}, "tcp", ip+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		subject := certs[0].Subject
		if strings.Contains(subject.CommonName, keyword) ||
			strings.Contains(strings.Join(subject.Organization, " "), keyword) ||
			strings.Contains(strings.Join(subject.OrganizationalUnit, " "), keyword) {
			return true
		}
	}

	return false
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func getAWSIpRangePrefixes(randomize bool) ([]string, error) {
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
