package main

import (
	"testing"
	"time"
)

func TestParseLogLine(t *testing.T) {

	type testData struct {
		logLine     string
		expectedLog *logRecord
	}

	x := []testData{
		{
			`127.0.0.1 - jill [09/May/2018:16:00:41 +0000] "GET /api/user HTTP/1.0" 200 234`,
			&logRecord{
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
			&logRecord{
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

// Test behaviour when QPS goes under the threshold
func TestUpdateAlertingSlow(t *testing.T) {
	s := &stats{}

	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 00, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 01, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 02, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 03, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 04, 00, 0, time.UTC)})

	qps, err := s.getQueryRate()
	if err != nil {
		t.Error(err)
	}
	if qps != 0.025 {
		t.Errorf("Expected QPS of 0.025 != %f", qps)
	}
	if s.alerting {
		t.Errorf("Unexpected alerting triggered")
	}
}

// Test behaviour when QPS goes over the threshold
func TestUpdateAlertingFast(t *testing.T) {
	s := &stats{}

	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 04, 1, 0, time.UTC)})
	for i := 0; i < 20; i++ {
		s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 04, 2, 0, time.UTC)})
	}

	qps, err := s.getQueryRate()
	if err != nil {
		t.Error(err)
	}
	if qps != 21.0 {
		t.Errorf("Expected QPS of 0.025 != %f", qps)
	}
	if !s.alerting {
		t.Errorf("Expected alerting to be triggered")
	}
}

// Test behaviour when no logs have been processed
func TestUpdateAlertingEmpty(t *testing.T) {
	s := &stats{}

	_, err := s.getQueryRate()
	if err == nil {
		t.Errorf("Expected error when logs window is empty")
	}
	if s.alerting {
		t.Errorf("Unexpected alerting triggered")
	}
}

// Test alerting condition is able to flap between not alerting, alerting, and back
// to not alerting
func TestUpdateAlertinFlap(t *testing.T) {
	s := &stats{}

	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 00, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 01, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 02, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 03, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 04, 00, 0, time.UTC)})
	if s.alerting {
		t.Errorf("Unexpected alerting triggered")
	}

	// Makes average QPS go exactly at 10.0 (62 seconds elapsed between first and last request
	// for a total of 620 requests)
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 05, 1, 0, time.UTC)})
	for i := 0; i < 618; i++ {
		s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 05, 2, 0, time.UTC)})
	}
	if s.alerting {
		t.Errorf("Unexpected alerting triggered")
	}

	// Makes average QPS go above 10.0
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 10, 05, 2, 0, time.UTC)})
	if !s.alerting {
		t.Errorf("Expected alerting to be triggered")
	}

	// Two queries arrive consecutively after 1 hour, which should yield a query rate of
	// 2 queries per second
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 11, 00, 00, 0, time.UTC)})
	s.updateAlerting(&logRecord{Timestamp: time.Date(2019, 01, 01, 11, 00, 01, 0, time.UTC)})
	if s.alerting {
		t.Errorf("Unexpected alerting triggered")
	}
}
