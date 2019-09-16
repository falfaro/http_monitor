package main

import (
	"testing"
	"time"
)

func TestParseLogLine(t *testing.T) {

	type testData struct {
		logLine     string
		expectedLog *Log
	}

	x := []testData{
		{
			`127.0.0.1 - jill [09/May/2018:16:00:41 +0000] "GET /api/user HTTP/1.0" 200 234`,
			&Log{
				IP:         "127.0.0.1",
				Identity:   "-",
				User:       "jill",
				Timestamp:  time.Date(2018, 5, 9, 16, 00, 41, 0, time.UTC),
				Action:     "GET",
				Section:    "/api",
				Resource:   "/user",
				Protocol:   "HTTP/1.0",
				StatusCode: 200,
				Size:       234,
			},
		},
		{
			`127.0.0.1 - james [09/May/2018:16:00:39 +0000] "GET /report HTTP/1.0" 200 123`,
			&Log{
				IP:         "127.0.0.1",
				Identity:   "-",
				User:       "james",
				Timestamp:  time.Date(2018, 5, 9, 16, 00, 39, 0, time.UTC),
				Action:     "GET",
				Section:    "/report",
				Protocol:   "HTTP/1.0",
				StatusCode: 200,
				Size:       123,
			},
		},
	}

	for _, elem := range x {
		actualLog, err := parseLogLine(elem.logLine)
		if err != nil {
			t.Errorf("Error %s while parsing log line %s", err, elem.logLine)
		}
		if *actualLog != *elem.expectedLog {
			t.Errorf("%+v != %+v", elem.expectedLog, actualLog)
		}
	}
}
