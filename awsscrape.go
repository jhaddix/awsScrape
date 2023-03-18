
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
)

type IPRange struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
	} `json:"prefixes"`
}

func main() {
	keyword := flag.String("keyword", "", "Keyword to search in SSL certificates")
	flag.Parse()

	if *keyword == "" {
		fmt.Println("Usage: go run script.go -keyword=<your_keyword>")
		return
	}

	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		fmt.Println("Error fetching IP ranges:", err)
		return
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var ipRanges IPRange
	err = json.Unmarshal(data, &ipRanges)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}

	var wg sync.WaitGroup
	ipChan := make(chan string)

	for _, prefix := range ipRanges.Prefixes {
		wg.Add(1)
		go func(ipRange string) {
			defer wg.Done()
			checkIPRange(ipRange, *keyword, ipChan)
		}(prefix.IPPrefix)
	}

	go func() {
		wg.Wait()
		close(ipChan)
	}()

	for ip := range ipChan {
		fmt.Printf("Keyword found in SSL certificate for IP: %s\n", ip)
	}
}

func checkIPRange(ipRange, keyword string, ipChan chan<- string) {
	_, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return
	}

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		if checkSSLKeyword(ip.String(), keyword) {
			ipChan <- ip.String()
		}
	}
}

func checkSSLKeyword(ip, keyword string) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 1e9}, "tcp", ip+":443", &tls.Config{InsecureSkipVerify: true})
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
