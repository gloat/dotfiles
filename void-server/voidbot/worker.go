package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// The Worker's admin route (.workers/void-media/src/op.js), the same one optool uses.
type Worker struct {
	url, token string
	http       *http.Client
}

func newWorker(c *Config) *Worker {
	return &Worker{url: c.AdminURL, token: c.AdminToken, http: &http.Client{Timeout: 20 * time.Second}}
}

// Event is one row of the Ledger's queue: id/at/kind plus the kind's own fields.
type Event map[string]any

func (e Event) str(k string) string {
	if v, ok := e[k].(string); ok {
		return v
	}
	return ""
}

func (e Event) num(k string) float64 {
	v, _ := e[k].(float64)
	return v
}

func (e Event) flag(k string) bool {
	v, _ := e[k].(bool)
	return v
}

func (e Event) kind() string { return e.str("kind") }

type EventPage struct {
	Events []Event `json:"events"`
	Last   int64   `json:"last"`
	More   bool    `json:"more"`
	Paused bool    `json:"paused"`
	Used   float64 `json:"used"`
	Budget float64 `json:"budget"`
}

type Status struct {
	Paused   bool     `json:"paused"`
	Stored   float64  `json:"stored"`
	Reserved float64  `json:"reserved"`
	InFlight int      `json:"inFlight"`
	Budget   float64  `json:"budget"`
	Channels []string `json:"channels"`
}

type Pending struct {
	Files  int     `json:"files"`
	Bytes  float64 `json:"bytes"`
	Newest []struct {
		Key  string  `json:"key"`
		Size float64 `json:"size"`
		At   int64   `json:"at"`
	} `json:"newest"`
}

func (w *Worker) call(body map[string]any, out any) error {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", w.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+w.token)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", "Mozilla/5.0 (voidbot)") // like optool: a browser-ish UA
	res, err := w.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("admin %v: HTTP %d %.200s", body["action"], res.StatusCode, data)
	}
	return json.Unmarshal(data, out)
}

func (w *Worker) events(after int64) (*EventPage, error) {
	var p EventPage
	return &p, w.call(map[string]any{"action": "events", "after": after, "limit": 200}, &p)
}

// the newest event id, so a first start doesn't replay two weeks of queue
func (w *Worker) newestID() (int64, error) {
	var p EventPage
	err := w.call(map[string]any{"action": "events", "tail": 1}, &p)
	return p.Last, err
}

// action = status | pause | resume
func (w *Worker) status(action, by string) (*Status, error) {
	var s Status
	return &s, w.call(map[string]any{"action": action, "by": by}, &s)
}

func (w *Worker) pending() (*Pending, error) {
	var p Pending
	return &p, w.call(map[string]any{"action": "pending"}, &p)
}
