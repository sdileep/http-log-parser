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

const (
	// ErrOpeningFile :
	ErrOpeningFile = "error opening file"
)

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
			// TODO: stream somewhere else
			fmt.Println(fmt.Sprintf("error: %+v", err))
		}
	}()

	lineCount := 0
	uniqueIps := make(map[string]int)
	urlHits := make(map[string]int)
	for line := range lineCh {
		count, exists := uniqueIps[line.RemoteHost]
		if !exists {
			uniqueIps[line.RemoteHost] = 0
		}
		uniqueIps[line.RemoteHost] = count + 1

		count, exists = urlHits[line.URL]
		if !exists {
			urlHits[line.URL] = 0
		}
		urlHits[line.URL] = count + 1

		lineCount++
	}

	type ipStat struct {
		address string
		count   int
	}
	type urlStat struct {
		address string
		count   int
	}

	ipStats := make([]*ipStat, 0, len(uniqueIps))
	for k, v := range uniqueIps {
		ipStats = append(ipStats, &ipStat{
			address: k,
			count:   v,
		})
	}
	sort.Slice(ipStats, func(i, j int) bool {
		return ipStats[i].count > ipStats[j].count
	})
	var mostActiveIPs []string
	for i := 0; i < l.mostActiveIPsCount; i++ {
		mostActiveIPs = append(mostActiveIPs, ipStats[i].address)
	}

	urlStats := make([]*urlStat, 0, len(urlHits))
	for k, v := range urlHits {
		urlStats = append(urlStats, &urlStat{
			address: k,
			count:   v,
		})
	}
	sort.Slice(urlStats, func(i, j int) bool {
		return urlStats[i].count > urlStats[j].count
	})
	var mostVisitedURLs []string
	for i := 0; i < l.mostVisitedURLsCount; i++ {
		mostVisitedURLs = append(mostVisitedURLs, urlStats[i].address)
	}

	return &LogAnalytics{
		UniqueIPCount:   len(uniqueIps),
		MostActiveIPs:   mostActiveIPs,
		MostVisitedURLs: mostVisitedURLs,
	}, nil

}

// LogAnalyzerConfig :
type LogAnalyzerConfig struct {
	LineRegex            *regexp.Regexp
	MostActiveIPsCount   int
	MostVisitedURLsCount int
}

const (
	//ErrConfigIsRequired :
	ErrConfigIsRequired = "config is required"
	// ErrLineRegexIsRequired :
	ErrLineRegexIsRequired = "line regex is required"
)

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
