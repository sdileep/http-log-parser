package analyzer

import (
	"bufio"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

const (
	//ErrConfigIsRequired :
	ErrConfigIsRequired = "config is required"
	// ErrLineRegexIsRequired :
	ErrLineRegexIsRequired = "line regex is required"
	// ErrOpeningFile :
	ErrOpeningFile = "error opening file"
)

// LogAnalytics :
type LogAnalytics struct {
	// UniqueIPCount : The number of unique IP addresses
	UniqueIPCount int
	// Most active IP addresses
	MostActiveIPs []string
	// Most visited URLs
	MostVisitedURLs []string
}

// LogAnalyzer :
type LogAnalyzer interface {
	Analyze(filePath string) (*LogAnalytics, error)
}
type logAnalyzer struct {
	lineRegex            *regexp.Regexp
	mostActiveIPsCount   int
	mostVisitedURLsCount int
}

// Line : Represents a line in the log
type Line struct {
	RemoteHost string
	Time       time.Time
	Request    string
	Status     int
	Bytes      int
	Referer    string
	UserAgent  string
	URL        string
}

const ()

func (l *logAnalyzer) Analyze(filePath string) (*LogAnalytics, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.New(ErrOpeningFile)
	}
	defer file.Close()

	lineCh, errCh := readLogLines(file, l.lineRegex)
	go func() {
		err := <-errCh
		if err != nil {
			// TODO: stream somewhere else. Skipping bad lines intentionally
			fmt.Println(fmt.Sprintf("error: %+v", err))
		}
	}()

	uniqueIps := make(map[string]int)
	urlHits := make(map[string]int)
	for line := range lineCh {
		// consolidate IP metrics
		count, exists := uniqueIps[line.RemoteHost]
		if !exists {
			uniqueIps[line.RemoteHost] = 0
		}
		uniqueIps[line.RemoteHost] = count + 1

		// consolidate URL metrics
		count, exists = urlHits[line.URL]
		if !exists {
			urlHits[line.URL] = 0
		}
		urlHits[line.URL] = count + 1
	}

	mostActiveIPs := topMost(uniqueIps, l.mostActiveIPsCount)
	mostVisitedURLs := topMost(urlHits, l.mostVisitedURLsCount)

	return &LogAnalytics{
		UniqueIPCount:   len(uniqueIps),
		MostActiveIPs:   mostActiveIPs,
		MostVisitedURLs: mostVisitedURLs,
	}, nil

}

func readLogLines(file *os.File, lineRegex *regexp.Regexp) (<-chan *Line, <-chan error) {
	outCh := make(chan *Line)
	errCh := make(chan error)
	go func() {
		defer close(outCh)
		defer close(errCh)

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			line := scanner.Text()
			result := lineRegex.FindStringSubmatch(line)
			// skip empty lines
			if len(result) <= 0 {
				continue
			}

			lineItem := &Line{
				RemoteHost: result[1],
				Request:    result[3] + " " + result[4] + " " + result[5],
				Referer:    result[9],
				UserAgent:  result[10],
			}

			value := result[2]
			layout := "02/Jan/2006:15:04:05 -0700"
			t, _ := time.Parse(layout, value)
			lineItem.Time = t

			status, err := strconv.Atoi(result[7])
			if err != nil {
				status = 0
			}
			lineItem.Status = status

			bytes, err := strconv.Atoi(result[8])
			if err != nil {
				bytes = 0
			}
			lineItem.Bytes = bytes

			url := result[4]
			altURL := result[6]
			if url == "" && altURL != "" {
				url = altURL
			}
			lineItem.URL = url

			outCh <- lineItem

			if err := scanner.Err(); err != nil {
				errCh <- err
			}
		}
	}()

	return outCh, errCh
}

func topMost(metrics map[string]int, top int) []string {
	type stat struct {
		address string
		count   int
	}

	// To retrieve The top m count:
	//  	collect IP specific metrics,
	//		sort the collected metrics by the count
	//		retrieve top m
	stats := make([]*stat, 0, len(metrics))
	for k, v := range metrics {
		stats = append(stats, &stat{
			address: k,
			count:   v,
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].count > stats[j].count
	})
	var topMost []string
	for i := 0; i < top; i++ {
		topMost = append(topMost, stats[i].address)
	}

	return topMost
}

// LogAnalyzerConfig :
type LogAnalyzerConfig struct {
	LineRegex            *regexp.Regexp
	MostActiveIPsCount   int
	MostVisitedURLsCount int
}

// NewLogAnalyzer : Returns a log analyzer that implements LogAnalyzer interface
func NewLogAnalyzer(config *LogAnalyzerConfig) (LogAnalyzer, error) {
	if config == nil {
		return nil, errors.New(ErrConfigIsRequired)
	}
	if config.LineRegex == nil {
		return nil, errors.New(ErrLineRegexIsRequired)
	}

	return &logAnalyzer{
		lineRegex:            config.LineRegex,
		mostActiveIPsCount:   config.MostActiveIPsCount,
		mostVisitedURLsCount: config.MostVisitedURLsCount,
	}, nil
}
