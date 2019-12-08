package analyzer

import (
	"bytes"
	"errors"
	"log"
	"reflect"
	"regexp"
	"testing"
)

func Test_logAnalyzer_Analyze(t *testing.T) {
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

	defaultLineRegex, err := regexp.Compile(buffer.String())
	if err != nil {
		log.Fatalf("regexp: %s", err)
	}

	type fields struct {
		lineRegex            *regexp.Regexp
		mostActiveIPsCount   int
		mostVisitedURLsCount int
	}
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *LogAnalytics
		wantErr error
	}{
		{
			name:    "error when wrong file path is provided",
			fields:  fields{lineRegex: defaultLineRegex},
			args:    args{filePath: "./test-data.log"},
			wantErr: errors.New(ErrOpeningFile),
		},
		// TODO: for lack of time, am not implementing the file format validations
		{
			name:   "analytics - unique ip counted returned, when file & format is as expected, matches expectation",
			fields: fields{lineRegex: defaultLineRegex},
			args:   args{filePath: "./test-data/programming-task.log"},
			want: &LogAnalytics{
				UniqueIPCount: 11,
			},
		},
		{
			name: "analytics - top 3 most visited urls",
			fields: fields{
				lineRegex:            defaultLineRegex,
				mostVisitedURLsCount: 3,
			},
			args: args{filePath: "./test-data/top-3-most-visited-urls.log"},
			want: &LogAnalytics{
				UniqueIPCount:   17,
				MostVisitedURLs: []string{"/intranet-analytics/", "http://example.net/faq/", "/docs/manage-websites/"},
			},
		},
		{
			name: "analytics - top 3 most active ips",
			fields: fields{
				lineRegex:          defaultLineRegex,
				mostActiveIPsCount: 3,
			},
			args: args{filePath: "./test-data/top-3-most-active-ips.log"},
			want: &LogAnalytics{
				UniqueIPCount: 15,
				MostActiveIPs: []string{"177.71.128.21", "168.41.191.40", "50.112.00.11"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &LogAnalyzerConfig{
				LineRegex:            tt.fields.lineRegex,
				MostActiveIPsCount:   tt.fields.mostActiveIPsCount,
				MostVisitedURLsCount: tt.fields.mostVisitedURLsCount,
			}
			l, err := NewLogAnalyzer(config)
			if err != nil {
				t.Errorf("logAnalyzer.Analyze() error = %v, error creating analyzer", err)
				return
			}
			got, err := l.Analyze(tt.args.filePath)
			// if tt.wantErr != nil && tt.wantErr.Error() != err.Error() {
			// 	t.Errorf("logAnalyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
			// 	return
			// }
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("logAnalyzer.Analyze() error is expected")
				}
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("logAnalyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("logAnalyzer.Analyze() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLogAnalyzer(t *testing.T) {
	type args struct {
		config *LogAnalyzerConfig
	}
	tests := []struct {
		name    string
		args    args
		want    *logAnalyzer
		wantErr error
	}{
		{
			name:    "error: no config",
			args:    args{},
			wantErr: errors.New(ErrConfigIsRequired),
		},
		{
			name: "error: no log line regex",
			args: args{
				config: &LogAnalyzerConfig{},
			},
			wantErr: errors.New(ErrLineRegexIsRequired),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewLogAnalyzer(tt.args.config)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("NewLogAnalyzer() error is expected")
				}
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("NewLogAnalyzer() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLogAnalyzer() = %v, want %v", got, tt.want)
			}
		})
	}
}
