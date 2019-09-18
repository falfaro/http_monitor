package main

import (
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

type stats struct {
	// Key is the HTTP Response/Status Code, typically collapsed into
	// `1XX`, `2XX`, `3XX`, etc. to produce a less, more compact and
	// meaningful map.
	httpResponseCodes map[string]int
	sectionCounts     map[string]int
}

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

// Update stats
func updateStats(s *stats, log *Log) {
	// Generate a 1XX, 2XX, 3XX, 4XX or 5XX string from the response code
	responseCode := fmt.Sprintf("%d", log.StatusCode)
	responseCode = fmt.Sprintf("%cXX", responseCode[0])
	s.httpResponseCodes[responseCode]++
	s.sectionCounts[log.Section]++
}

// Dump stats to standard output
func dumpStats(s *stats) {
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

func main() {
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
		for {
			mutex.Lock()
			dumpStats(s)
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
		updateStats(s, parsedLog)
		mutex.Unlock()
	}
}
