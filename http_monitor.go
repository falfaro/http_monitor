package main

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

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

const strftime = "02/Jan/2006:15:04:05 +0000"

var logLineRegExp = regexp.MustCompile(`([^ ]+) (-) ([[:alnum:]]+) ` +
	// Timestamp
	`\[(\d{2}/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]` +
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
	`(\d+)`)

func parseLogLine(s string) (*Log, error) {
	var ts time.Time
	var err error
	var statusCode int
	var size int

	matched := logLineRegExp.FindStringSubmatch(s)

	if ts, err = time.Parse(strftime, matched[4]); err != nil {
		return nil, err
	}

	if statusCode, err = strconv.Atoi(matched[10]); err != nil {
		return nil, err
	}

	if size, err = strconv.Atoi(matched[11]); err != nil {
		return nil, err
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

func main() {
	s := "127.0.0.1 - jill [09/May/2018:16:00:41 +0000] \"GET /api/user HTTP/1.0\" 200 234"
	if log, err := parseLogLine(s); err == nil {
		fmt.Printf("%+v\n", log)
	}
}
