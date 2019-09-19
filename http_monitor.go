package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/hpcloud/tail"
)

// Timestamp format used in W3C-formatted access logs
const strftime = "_2/Jan/2006:15:04:05 -0700"

// Command-line flag to override average QPS threshold for high-traffic alerts
var qpsThreshold = flag.Float64("qps", 10.0, "Average QPS threshold for high-traffic alerts")

// Command-line flag to override N when printing top(N) sections
var topN = flag.Int("top", 5, "Dump top N sections")

// Command-line flag to override access log filename
var fileName = flag.String("filename", "access.log", "Pathname to the access log file")

// Log record
type logRecord struct {
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
	logsInWindow      []*logRecord   // Stores last seen records in the high-traffic alerting window
	alerting          bool           // Currently alerting?
}

// Regular expression for matching (and parsing) W3C-formatted access logs
var logLineRegExp = regexp.MustCompile(`([^ ]+) ` +
	// Identity
	`(-) ` +
	// User
	`([0-9A-Za-z-]+) ` +
	// User
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
func parseLogLine(s string) (*logRecord, error) {
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

	return &logRecord{
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

// Compute the delta (time difference in seconds) between first and last
// log record inside the existing window
func (s *stats) getDelta() float64 {
	n := len(s.logsInWindow)
	if n > 0 {
		start := s.logsInWindow[0]
		end := s.logsInWindow[n-1]
		return end.Timestamp.Sub(start.Timestamp).Seconds()
	}
	return 0.0
}

// Update stats used to trigger high-traffic alerting
func (s *stats) updateAlerting(log *logRecord) {
	s.logsInWindow = append(s.logsInWindow, log)

	// Pop log records from the beginning of the window until the size of
	// window is less or equal to 2 minutes (120 seconds)
	for len(s.logsInWindow) > 0 && s.getDelta() > 120.0 {
		s.logsInWindow = s.logsInWindow[1:]
	}

	// Alert if QPS > average QPS threshold
	if qps, err := s.getQueryRate(); err == nil {
		s.alerting = (qps > *qpsThreshold)
	}
}

// Update stats
func (s *stats) updateStats(log *logRecord) {
	// Generate a 1XX, 2XX, 3XX, 4XX or 5XX string from the response code
	responseCode := fmt.Sprintf("%d", log.StatusCode)
	responseCode = fmt.Sprintf("%cXX", responseCode[0])
	s.httpResponseCodes[responseCode]++
	s.sectionCounts[log.Section]++
	s.updateAlerting(log)
}

// Dump stats to standard output
func (s *stats) dumpStats() {
	var w = new(tabwriter.Writer)
	w.Init(os.Stdout, 8, 0, 1, ' ', tabwriter.AlignRight)
	s.dumpResponseCodes(w)
	s.dumpTopSections(w, *topN)
	fmt.Fprint(w, "---\n")
	w.Flush()
}

// Dump HTTP response codes to standard output
func (s *stats) dumpResponseCodes(w *tabwriter.Writer) {
	fmt.Printf("Response codes:\n")

	var keys []string
	for k := range s.httpResponseCodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Fprintf(w, "%d\t(HTTP/%s)\t", s.httpResponseCodes[k], k)
	}
	fmt.Fprintln(w)
}

// Dumps the top N sections to standard output
func (s *stats) dumpTopSections(w *tabwriter.Writer, n int) {
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
	fmt.Fprintf(w, "Top %d sections:\n", n)
	for i, v := range counts {
		if i >= n {
			break
		}
		fmt.Fprintf(w, "%d\t %s\n", v.count, v.section)
	}
}

// Compute average query rate (qps)
func (s *stats) getQueryRate() (float64, error) {
	n := len(s.logsInWindow)
	if n > 0 {
		delta := s.logsInWindow[n-1].Timestamp.Sub(s.logsInWindow[0].Timestamp).Seconds()
		return float64(n) / delta, nil
	}
	return math.Inf(1), fmt.Errorf("Logs window is empty")
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

	mutex := &sync.Mutex{}

	// Gorutine that periodically dumps stats to standard output, as well as
	// signaling when a high-traffic condition is triggered or abandoned
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
	t, err := tail.TailFile(*fileName, tail.Config{Follow: true})
	if err != nil {
		log.Panicf("Cannot tail file: %s", *fileName)
	}
	for line := range t.Lines {
		parsedLog, err := parseLogLine(line.Text)
		if err != nil {
			log.Panicf("Cannot parse log line: %s", line.Text)
		}
		mutex.Lock()
		s.updateStats(parsedLog)
		mutex.Unlock()
	}
}
