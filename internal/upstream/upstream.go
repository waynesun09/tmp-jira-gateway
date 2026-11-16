// Package upstream holds the Atlassian credentials: it fetches and caches
// client_credentials access tokens and forwards allowed calls.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/audit"
)

const (
	maxTokenResponseBytes = 64 << 10
	maxTokenLifetime      = 24 * time.Hour
	// maxExpirySkew caps how long before expiry a cached token is
	// replaced; the skew is half the lifetime up to this cap.
	maxExpirySkew = 5 * time.Minute
)

// Errors the server maps to fixed responses.
var (
	ErrToken            = errors.New("upstream token unavailable")
	ErrTransport        = errors.New("upstream unavailable")
	ErrResponseTooLarge = errors.New("upstream response too large")
)

// TokenSource obtains and caches access tokens for one OAuth client. The
// client id and secret are read from files on every fetch (so a rotated
// Secret Manager mount is picked up) and are never kept or logged.
type TokenSource struct {
	name       string // read or write, for the log
	idFile     string
	secretFile string
	tokenURL   string
	hc         *http.Client
	log        *audit.Logger
	now        func() time.Time

	sem    chan struct{}
	token  string
	expiry time.Time
}

// NewTokenSource returns a TokenSource for the client whose id and secret
// are in idFile and secretFile.
func NewTokenSource(name, idFile, secretFile, tokenURL string, hc *http.Client, log *audit.Logger) *TokenSource {
	return &TokenSource{
		name: name, idFile: idFile, secretFile: secretFile, tokenURL: tokenURL,
		hc: hc, log: log, now: time.Now, sem: make(chan struct{}, 1),
	}
}

// CheckFiles reports whether both credential files are readable and
// non-empty, without keeping their contents.
func (s *TokenSource) CheckFiles() error {
	for _, f := range []string{s.idFile, s.secretFile} {
		b, err := os.ReadFile(f)
		if err != nil || len(bytes.TrimSpace(b)) == 0 {
			return fmt.Errorf("%s client: credential file %s is missing or empty", s.name, f)
		}
	}
	return nil
}

// Token returns a valid access token. stale is a token the API just
// rejected: it is replaced rather than returned again. Concurrent callers
// share one fetch; waiting honours ctx.
func (s *TokenSource) Token(ctx context.Context, stale string) (string, error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-s.sem }()
	if s.token != "" && s.token != stale && s.now().Before(s.expiry) {
		return s.token, nil
	}
	s.token = ""
	tok, lifetime, status, outcome := s.fetch(ctx)
	s.log.TokenFetch(s.name, outcome, status)
	if outcome != "ok" {
		return "", ErrToken
	}
	skew := min(maxExpirySkew, lifetime/2)
	s.token = tok
	s.expiry = s.now().Add(lifetime - skew)
	return tok, nil
}

// fetch performs the client_credentials grant. outcome is "ok" or a fixed
// failure word; nothing from the response body is returned except the
// token itself.
func (s *TokenSource) fetch(ctx context.Context) (tok string, lifetime time.Duration, status int, outcome string) {
	id, err1 := os.ReadFile(s.idFile)
	secret, err2 := os.ReadFile(s.secretFile)
	if err1 != nil || err2 != nil {
		return "", 0, 0, "credential_file_unreadable"
	}
	body, err := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     strings.TrimSpace(string(id)),
		"client_secret": strings.TrimSpace(string(secret)),
	})
	if err != nil {
		return "", 0, 0, "encode_failed"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", 0, 0, "request_failed"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return "", 0, 0, "transport_error"
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil || len(data) > maxTokenResponseBytes {
		return "", 0, resp.StatusCode, "bad_response"
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, resp.StatusCode, "rejected"
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &tr); err != nil || tr.AccessToken == "" || tr.ExpiresIn <= 0 ||
		(tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "Bearer")) {
		return "", 0, resp.StatusCode, "bad_response"
	}
	lifetime = maxTokenLifetime
	if tr.ExpiresIn < int64(maxTokenLifetime/time.Second) {
		lifetime = time.Duration(tr.ExpiresIn) * time.Second
	}
	return tr.AccessToken, lifetime, resp.StatusCode, "ok"
}

// Forwarder sends allowed calls to the Atlassian API gateway.
type Forwarder struct {
	base    string
	hc      *http.Client
	read    *TokenSource
	write   *TokenSource
	maxResp int64
}

// NewForwarder returns a Forwarder. read or write may be nil when no
// grant uses that level.
func NewForwarder(base string, hc *http.Client, read, write *TokenSource, maxResp int64) *Forwarder {
	return &Forwarder{base: strings.TrimRight(base, "/"), hc: hc, read: read, write: write, maxResp: maxResp}
}

// NewHTTPClient returns the client for upstream calls: a timeout and no
// redirects (a redirect is returned to the server as a 3xx).
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Result is an upstream answer.
type Result struct {
	Status      int
	ContentType string
	RetryAfter  string
	Body        []byte
}

// Do forwards one call with the write client for a write grant and the
// read client otherwise. The request is built from scratch: no header of
// the caller's (Authorization, hop-by-hop or other) is copied. An upstream
// 401 gets one token refresh and one retry.
func (f *Forwarder) Do(ctx context.Context, write bool, method, path, rawQuery string, body []byte) (*Result, error) {
	ts := f.read
	if write {
		ts = f.write
	}
	if ts == nil {
		return nil, ErrToken
	}
	target := f.base + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	var stale string
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := ts.Token(ctx, stale)
		if err != nil {
			return nil, err
		}
		var rb io.Reader
		if body != nil {
			rb = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, rb)
		if err != nil {
			return nil, ErrTransport
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "fullsend-jira-gateway")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := f.hc.Do(req)
		if err != nil {
			return nil, ErrTransport
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, f.maxResp+1))
		resp.Body.Close()
		if err != nil {
			return nil, ErrTransport
		}
		if int64(len(data)) > f.maxResp {
			return nil, ErrResponseTooLarge
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			stale = tok
			continue
		}
		return &Result{
			Status:      resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			RetryAfter:  resp.Header.Get("Retry-After"),
			Body:        data,
		}, nil
	}
	return nil, ErrTransport // not reached: attempt 1 always returns
}
