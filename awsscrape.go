package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type IPRange struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
	} `json:"prefixes"`
}

const (
	defaultTimeout = 10 * time.Second
)

var (
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)

	// Flags
	wordlistFileFlag = flag.String("wordlistFile", "", "Path to a file containing one word per line")
	timeoutFlag      = flag.Duration("timeout", defaultTimeout, "Timeout for network operations")
	threadsFlag      = flag.Int("threads", 1, "Number of concurrent threads to use")
)

type CheckIPRangeError struct {
	IPRange string
	Err     error
}

func (e CheckIPRangeError) Error() string {
	return fmt.Sprintf("error checking IP range %s: %v", e.IPRange, e.Err)
}

func main() {
	flag.Parse()

	if *wordlistFileFlag == "" {
		fmt.Printf("Usage: %s -wordlistFile=<path_to_wordlist_file>\n", os.Args[0])
		os.Exit(1)
	}

	wordlist, err := readWordlist(*wordlistFileFlag)
	if err != nil {
		logger.Fatalf("Error reading wordlist file: %v", err)
	}

	ipRanges, err := getIPRanges()
	if err != nil {
		logger.Fatalf("Error fetching IP ranges: %v", err)
	}

	ipAddresses := &sync.Map{}
	eg := &errgroup.Group{}
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	threadCount := *threadsFlag
	if threadCount <= 0 {
		threadCount = 1
	}
	rangeCount := len(ipRanges.Prefixes)
	rangesPerThread := (rangeCount + threadCount - 1) / threadCount

	for i := 0; i < rangeCount; i += rangesPerThread {
		start := i
		end := i + rangesPerThread
		if end > rangeCount {
			end = rangeCount
		}
		eg.Go(func() error {
			for j := start; j < end; j++ {
				err := checkIPRange(ctx, ipRanges.Prefixes[j].IPPrefix, wordlist, ipAddresses)
				if err != nil {
					return CheckIPRangeError{ipRanges.Prefixes[j].IPPrefix, err}
				}
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		logger.Fatalf("%v", err)
	}

	ipAddresses.Range(func(key, value interface{}) bool {
		matchedWords := value.([]string)
		logger.Printf("Word(s) found in SSL certificate for IP: %s\nMatched wordlist: %v\n", key, matchedWords)
		return true
	})
}

func readWordlist(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("error opening wordlist file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var wordlist []string
	for scanner.Scan() {
		word := strings
