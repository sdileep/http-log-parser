package main

import (
	"bytes"
	"fmt"
	"log"
	"regexp"

	"github.com/sdileep/http-log-parser/analyzer"
)

func main() {
	var buffer bytes.Buffer
	buffer.WriteString(`^(\S+)\s`)                  // 1) IP
	buffer.WriteString(`\S+\s+`)                    // remote logname
	buffer.WriteString(`(?:\S+\s+)+`)               // remote user
	buffer.WriteString(`\[([^]]+)\]\s`)             // 2) date
	buffer.WriteString(`"(\S*)\s?`)                 // 3) method
	buffer.WriteString(`(?:((?:[^"]*(?:\\")?)*)\s`) // 4) URL
	buffer.WriteString(`([^"]*)"\s|`)               // 5) protocol
	buffer.WriteString(`((?:[^"]*(?:\\")?)*)"\s)`)  // 6) or, possibly URL with no protocol
	buffer.WriteString(`(\S+)\s`)                   // 7) status code
	buffer.WriteString(`(\S+)\s`)                   // 8) bytes
	buffer.WriteString(`"((?:[^"]*(?:\\")?)*)"\s`)  // 9) referrer
	buffer.WriteString(`"(.*)"$`)                   // 10) user agent

	lineRegex, err := regexp.Compile(buffer.String())
	if err != nil {
		log.Fatalf("regexp: %s", err)
	}
	logAnalyzer, err := analyzer.NewLogAnalyzer(&analyzer.LogAnalyzerConfig{
		LineRegex:            lineRegex,
		MostActiveIPsCount:   4,
		MostVisitedURLsCount: 3,
	})

	analytics, err := logAnalyzer.Analyze("./analyzer/test-data/programming-task.log")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("unique ips count: %d\n", analytics.UniqueIPCount)
	fmt.Printf("most visited urls: %v\n", analytics.MostVisitedURLs)
	fmt.Printf("most active ips: %v\n", analytics.MostActiveIPs)
}
