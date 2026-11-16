// Package audit writes one JSON line per request and per upstream token
// fetch. It has no field for tokens, bodies or JQL text, so they cannot be
// logged by mistake.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Logger writes JSON lines to w.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	instance string
	now      func() time.Time
}

// New returns a Logger with a random instance id, so log lines from one
// process (one Cloud Run instance) can be told apart.
func New(w io.Writer) *Logger {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &Logger{w: w, instance: hex.EncodeToString(b), now: time.Now}
}

// Instance returns the instance id.
func (l *Logger) Instance() string { return l.instance }

// Request is one request's audit record.
type Request struct {
	Repository     string
	RunID          string
	Method         string
	Template       string // path template, never the raw path
	Decision       string // allow or deny
	Reason         string // fixed denial reason
	UpstreamStatus int    // 0 when nothing was sent upstream
	Status         int    // status returned to the caller
	Latency        time.Duration
	JQLSHA256      string // search calls only: a hash, never the text
}

type requestLine struct {
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	Time           string `json:"time"`
	Instance       string `json:"instance"`
	Repository     string `json:"repository,omitempty"`
	RunID          string `json:"run_id,omitempty"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason,omitempty"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	Status         int    `json:"status"`
	LatencyMS      int64  `json:"latency_ms"`
	JQLSHA256      string `json:"jql_sha256,omitempty"`
}

// Request logs one request.
func (l *Logger) Request(r Request) {
	sev := "INFO"
	if r.Decision != "allow" {
		sev = "WARNING"
	}
	path := r.Template
	if path == "" {
		path = "unmatched"
	}
	l.write(requestLine{
		Severity: sev, Message: "request", Time: l.ts(), Instance: l.instance,
		Repository: r.Repository, RunID: r.RunID, Method: r.Method, Path: path,
		Decision: r.Decision, Reason: r.Reason, UpstreamStatus: r.UpstreamStatus, Status: r.Status,
		LatencyMS: r.Latency.Milliseconds(), JQLSHA256: r.JQLSHA256,
	})
}

type tokenLine struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Time     string `json:"time"`
	Instance string `json:"instance"`
	Client   string `json:"client"`
	Outcome  string `json:"outcome"`
	Status   int    `json:"token_endpoint_status,omitempty"`
}

// TokenFetch logs one upstream token request: which OAuth client (read or
// write) and the outcome (ok, or a fixed failure word).
func (l *Logger) TokenFetch(client, outcome string, status int) {
	sev := "INFO"
	if outcome != "ok" {
		sev = "ERROR"
	}
	l.write(tokenLine{Severity: sev, Message: "token_fetch", Time: l.ts(), Instance: l.instance, Client: client, Outcome: outcome, Status: status})
}

type eventLine struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Time     string `json:"time"`
	Instance string `json:"instance"`
	Detail   string `json:"detail,omitempty"`
}

// Event logs a lifecycle message (startup, shutdown). detail must be a
// fixed or operator-supplied string, never request content.
func (l *Logger) Event(severity, message, detail string) {
	l.write(eventLine{Severity: severity, Message: message, Time: l.ts(), Instance: l.instance, Detail: detail})
}

func (l *Logger) ts() string { return l.now().UTC().Format(time.RFC3339Nano) }

func (l *Logger) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(b)
}
