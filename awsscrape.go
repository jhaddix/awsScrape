package main

import (
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
		Service  string `json:"service"`
	} `json:"prefixes"`
}

type checkIPRangeParams struct {
	ipRange     string
	keywordList []string
	timeout     int
	verbose     bool
}

func parseCommandLineArguments() (string, string, int, int, bool, string, bool) {
	wordlist := flag.String("wordlist", "", "File containing keywords to search in SSL certificates")
	shortWordlist := flag.String("w", "", "File containing keywords to search in SSL certificates (short form)")
	keyword := flag.String("keyword", "", "Single keyword to search in SSL certificates")
	numThreads := flag.Int("threads", 4, "Number of concurrent threads")
	timeout := flag.Int("timeout", 1, "Timeout in seconds for SSL connection")
	randomize := flag.Bool("randomize", false, "Randomize the order in which IP addresses are checked")
	outputFile := flag.String("output", "", "Output file to save results")
	verbose := flag.Bool("verbose", false, "Enable verbose mode")
	flag.BoolVar(verbose, "v", false, "Enable verbose mode (short form)")
	flag.Parse()

	if *wordlist == "" && *shortWordlist != "" {
		*wordlist = *shortWordlist
	}

	return *wordlist, *keyword, *numThreads, *timeout, *randomize, *outputFile, *verbose
}

func main() {
	wordlist, keyword, numThreads, timeout, randomize, outputFile, verbose := parseCommandLineArguments()

	if wordlist == "" && keyword == "" {
		fmt.Println("Usage: go run script.go [-wordlist=<your_keywords_file> | -keyword=<your_keyword>] [-threads=<num_threads>] [-timeout=<timeout_seconds>] [-randomize] [-output=<output_file>] [-verbose]")
		return
	}

	var keywordList []string
	if wordlist != "" {
		keywords, err := ioutil.ReadFile(wordlist)
		if err != nil {
			log.Println("Error reading wordlist file:", err)
			return
		}
		lines := strings.Split(string(keywords), "\n")
		for _, line := range lines {
			if len(strings.TrimSpace(line)) > 0 {
				keywordList = append(keywordList, line)
			}
		}
	} else {
		keywordList = []string{keyword}
	}

	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		log.Println("Error fetching IP ranges:", err)
		return
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return
	}

	var ipRanges IPRange
	err = json.Unmarshal(data, &ipRanges)
	if err != nil {
		log.Println("Error parsing JSON:", err)
		return
	}

	selectedIPRanges := filterIPRanges(ipRanges)

	if randomize {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(selectedIPRanges), func(i, j int) {
			selectedIPRanges[i], selectedIPRanges[j] = selectedIPRanges[j], selectedIPRanges[i]
		})
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
		for _, prefix := range selectedIPRanges {
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

func filterIPRanges(ipRanges IPRange) []string {
	var selectedRanges []string

	for _, ipRange := range ipRanges.Prefixes {
		if ipRange.Service == "EC2" || ipRange.Service == "CLOUDFRONT" {
			selectedRanges = append(selectedRanges, ipRange.IPPrefix)
		}
	}
	return selectedRanges
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
