package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hpcloud/tail"
)

// Timestamp format used in W3C-formatted access logs
const strftime = "_2/Jan/2006:15:04:05 -0700"

// Command-line flag to override average QPS threshold for high-traffic alerts
var qpsThreshold = flag.Float64("qps", 10.0, "Average QPS threshold for high-traffic alerts")

// Log record
type Log struct {
	IP         string
	Identity   string
	User       string
	Timestamp  time.Time
	Action     string
	Section    string
	Resource   string
	Protocol   string
	StatusCode int
	Size       int
}

// Internal stats
type stats struct {
	httpResponseCodes map[string]int // Keeps counters for each HTTP response code
	sectionCounts     map[string]int // Keeps counters for each seen section
	logsInWindow      []*Log         // Stores last seen records in the high-traffic alerting window
	alerting          bool           // Currently alerting?
}

// Regular expression for matching (and parsing) W3C-formatted access logs
var logLineRegExp = regexp.MustCompile(`([^ ]+) (-) ([0-9A-Za-z-]+) ` +
	// Timestamp
	`\[(\d{2}/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]` +
	// Methpd
	` \"(GET|POST|PUT|HEAD|DELETE|OPTIONS) ` +
	// Section
	`(/[^/ ]*)` +
	// Resource
	`([^ ]*) ` +
	// Protocol
	`(HTTP/\d\.\d)" ` +
	// Status code
	`(\d{3}) ` +
	// Size
	`([0-9-]+)`)

// Parse a W3C-formatted access log
func parseLogLine(s string) (*Log, error) {
	var ts time.Time
	var err error
	var statusCode int
	var size int

	matched := logLineRegExp.FindStringSubmatch(s)
	if len(matched) < 11 {
		log.Panicf("Error parsing log line: %s", s)
	}

	if ts, err = time.ParseInLocation(strftime, matched[4], time.UTC); err != nil {
		return nil, err
	}

	if statusCode, err = strconv.Atoi(matched[10]); err != nil {
		return nil, err
	}

	if size, err = strconv.Atoi(matched[11]); err != nil {
		size = 0
	}

	return &Log{
		IP:         matched[1],
		Identity:   matched[2],
		User:       matched[3],
		Timestamp:  ts,
		Action:     matched[6],
		Section:    matched[7],
		Resource:   matched[8],
		Protocol:   matched[9],
		StatusCode: statusCode,
		Size:       size,
	}, nil
}

// Update stats used to trigger high-traffic alerting
func (s *stats) updateAlerting(log *Log) {
	s.logsInWindow = append(s.logsInWindow, log)

	n := len(s.logsInWindow)
	var delta float64
	for delta = s.logsInWindow[n-1].Timestamp.Sub(s.logsInWindow[0].Timestamp).Seconds(); n > 0 && delta > 120.0; {
		s.logsInWindow = s.logsInWindow[1:]
		n--
		delta = s.logsInWindow[n-1].Timestamp.Sub(s.logsInWindow[0].Timestamp).Seconds()
	}
	// Alert if QPS > average QPS threshold
	if qps, err := s.getQueryRate(); err == nil {
		s.alerting = (qps > *qpsThreshold)
	}
}

// Update stats
func (s *stats) updateStats(log *Log) {
	// Generate a 1XX, 2XX, 3XX, 4XX or 5XX string from the response code
	responseCode := fmt.Sprintf("%d", log.StatusCode)
	responseCode = fmt.Sprintf("%cXX", responseCode[0])
	s.httpResponseCodes[responseCode]++
	s.sectionCounts[log.Section]++
	s.updateAlerting(log)
}

// Dump stats to standard output
func (s *stats) dumpStats() {
	fmt.Println("---")
	dumpResponseCodes(s)
	dumpTopSections(s, 5)
}

// Dump HTTP response codes to standard output
func dumpResponseCodes(s *stats) {
	fmt.Printf("Response codes:\n")

	var keys []string
	for k := range s.httpResponseCodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("%10d (%s)\n", s.httpResponseCodes[k], k)
	}
}

// Dumps the top N sections to standard output
func dumpTopSections(s *stats, n int) {
	type sectionCountPair struct {
		count   int
		section string
	}

	counts := make([]sectionCountPair, 0, len(s.sectionCounts))
	for section, count := range s.sectionCounts {
		counts = append(counts, sectionCountPair{count: count, section: section})
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].count > counts[j].count
	})
	fmt.Printf("Top %d sections:\n", n)
	for i, v := range counts {
		if i >= n {
			break
		}
		fmt.Printf("%10d (%s)\n", v.count, v.section)
	}
}

// Compute average query rate (qps)
func (s *stats) getQueryRate() (float64, error) {
	n := len(s.logsInWindow)
	if n > 0 {
		delta := s.logsInWindow[n-1].Timestamp.Sub(s.logsInWindow[0].Timestamp).Seconds()
		return float64(n) / delta, nil
	}
	return 0.0, fmt.Errorf("Logs window is empty")
}

func main() {
	// Parse command-line flags
	flag.Parse()

	s := &stats{
		sectionCounts: make(map[string]int),
		httpResponseCodes: map[string]int{
			"1XX": 0,
			"2XX": 0,
			"3XX": 0,
			"4XX": 0,
			"5XX": 0,
		},
	}

	var mutex = &sync.Mutex{}

	t, err := tail.TailFile("access.log", tail.Config{Follow: true})
	if err != nil {
		panic(err)
	}

	go func() {
		alerting := s.alerting
		for {
			mutex.Lock()

			s.dumpStats()
			// Display changes in high-traffic alerting
			if alerting && !s.alerting {
				fmt.Printf("High-traffic alerting not firing anymore\n")
			}
			if !alerting && s.alerting {
				qps, _ := s.getQueryRate()
				fmt.Printf("High-traffic alerting is firing at %f queries per second on average\n", qps)
			}

			mutex.Unlock()
			time.Sleep(10 * time.Second)
		}
	}()

	// Tail through the access log file
	for line := range t.Lines {
		// Make processing intentionally slower
		time.Sleep(500 * time.Microsecond)
		parsedLog, err := parseLogLine(line.Text)
		if err != nil {
			panic(err)
		}
		mutex.Lock()
		s.updateStats(parsedLog)
		mutex.Unlock()
	}
}
