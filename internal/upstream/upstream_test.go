package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/audit"
)

// fakeAtlassian stands in for both the token endpoint and the Jira API.
type fakeAtlassian struct {
	srv        *httptest.Server
	mu         sync.Mutex
	fetches    map[string]int // client_id → token requests
	issued     int64
	expiresIn  int64
	tokenBody  []map[string]string
	apiAuth    []string
	reject401  int32 // API answers 401 this many times
	apiStatus  int
	apiBody    string
	tokenFails bool
}

func newFake(t *testing.T) *fakeAtlassian {
	f := &fakeAtlassian{fetches: map[string]int{}, expiresIn: 3600, apiStatus: 200, apiBody: `{"ok":true}`}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAtlassian) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth/token" {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.tokenBody = append(f.tokenBody, body)
		f.fetches[body["client_id"]]++
		f.mu.Unlock()
		if f.tokenFails || r.Header.Get("Content-Type") != "application/json" || body["grant_type"] != "client_credentials" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"access_denied","error_description":"secret detail"}`)
			return
		}
		n := atomic.AddInt64(&f.issued, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("upstream-token-%s-%d", body["client_id"], n),
			"token_type":   "Bearer", "expires_in": f.expiresIn,
		})
		return
	}
	f.mu.Lock()
	f.apiAuth = append(f.apiAuth, r.Header.Get("Authorization"))
	f.mu.Unlock()
	if atomic.AddInt32(&f.reject401, -1) >= 0 {
		w.WriteHeader(401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.apiStatus)
	fmt.Fprint(w, f.apiBody)
}

func writeCreds(t *testing.T, id, secret string) (string, string) {
	d := t.TempDir()
	idf, sf := filepath.Join(d, "id"), filepath.Join(d, "secret")
	if err := os.WriteFile(idf, []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sf, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	return idf, sf
}

func setup(t *testing.T, f *fakeAtlassian) (*Forwarder, *TokenSource, *TokenSource, *bytes.Buffer) {
	var logBuf bytes.Buffer
	log := audit.New(&logBuf)
	hc := NewHTTPClient(5 * time.Second)
	ri, rs := writeCreds(t, "read-client", "read-secret-value")
	wi, ws := writeCreds(t, "write-client", "write-secret-value")
	read := NewTokenSource("read", ri, rs, f.srv.URL+"/oauth/token", hc, log)
	write := NewTokenSource("write", wi, ws, f.srv.URL+"/oauth/token", hc, log)
	return NewForwarder(f.srv.URL, hc, read, write, 1<<20), read, write, &logBuf
}

func TestTokenCachedAcrossCalls(t *testing.T) {
	f := newFake(t)
	fwd, _, _, logBuf := setup(t, f)
	for i := 0; i < 30; i++ {
		res, err := fwd.Do(context.Background(), false, "GET", "/ex/jira/c/rest/api/3/myself", "", nil)
		if err != nil || res.Status != 200 {
			t.Fatalf("call %d: %v %v", i, res, err)
		}
	}
	if f.fetches["read-client"] != 1 {
		t.Fatalf("token fetches = %d, want 1", f.fetches["read-client"])
	}
	if n := strings.Count(logBuf.String(), `"message":"token_fetch"`); n != 1 {
		t.Fatalf("token_fetch log lines = %d, want 1", n)
	}
	// The token request has the shape fullsend uses.
	b := f.tokenBody[0]
	if b["grant_type"] != "client_credentials" || b["client_id"] != "read-client" || b["client_secret"] != "read-secret-value" || len(b) != 3 {
		t.Fatalf("token request body = %v", b)
	}
}

func TestTokenRefreshBeforeExpiry(t *testing.T) {
	for _, c := range []struct {
		expiresIn int64
		refreshAt time.Duration // lifetime minus min(lifetime/2, 5 min)
	}{
		{3600, 3600*time.Second - 5*time.Minute},
		{60, 30 * time.Second},
	} {
		f := newFake(t)
		f.expiresIn = c.expiresIn
		_, read, _, _ := setup(t, f)
		now := time.Unix(1_800_000_000, 0)
		read.now = func() time.Time { return now }
		ctx := context.Background()
		t1, _ := read.Token(ctx, "")
		now = now.Add(c.refreshAt - time.Second)
		if t2, _ := read.Token(ctx, ""); t2 != t1 {
			t.Fatalf("expires_in %d: token replaced before %v", c.expiresIn, c.refreshAt)
		}
		now = now.Add(2 * time.Second)
		if t3, _ := read.Token(ctx, ""); t3 == t1 {
			t.Fatalf("expires_in %d: token not replaced after %v", c.expiresIn, c.refreshAt)
		}
		if f.fetches["read-client"] != 2 {
			t.Fatalf("fetches = %d", f.fetches["read-client"])
		}
	}
}

func TestReadWriteClientSplit(t *testing.T) {
	f := newFake(t)
	fwd, _, _, _ := setup(t, f)
	ctx := context.Background()
	if _, err := fwd.Do(ctx, false, "GET", "/x", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fwd.Do(ctx, true, "POST", "/x", "", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if f.fetches["read-client"] != 1 || f.fetches["write-client"] != 1 {
		t.Fatalf("fetches = %v", f.fetches)
	}
	if !strings.HasPrefix(f.apiAuth[0], "Bearer upstream-token-read-client-") || !strings.HasPrefix(f.apiAuth[1], "Bearer upstream-token-write-client-") {
		t.Fatalf("upstream auth = %v", f.apiAuth)
	}
}

func TestUnauthorizedRefreshesOnce(t *testing.T) {
	f := newFake(t)
	f.reject401 = 1
	fwd, _, _, _ := setup(t, f)
	res, err := fwd.Do(context.Background(), false, "GET", "/x", "", nil)
	if err != nil || res.Status != 200 {
		t.Fatalf("%v %v", res, err)
	}
	if f.fetches["read-client"] != 2 || len(f.apiAuth) != 2 || f.apiAuth[0] == f.apiAuth[1] {
		t.Fatalf("fetches %v, auth %v", f.fetches, f.apiAuth)
	}

	// Two 401s in a row: one retry only, and the 401 comes back.
	f2 := newFake(t)
	f2.reject401 = 5
	fwd2, _, _, _ := setup(t, f2)
	res, err = fwd2.Do(context.Background(), false, "GET", "/x", "", nil)
	if err != nil || res.Status != 401 || len(f2.apiAuth) != 2 {
		t.Fatalf("%v %v, calls %d", res, err, len(f2.apiAuth))
	}
}

func TestTokenFailureIsNotLeaked(t *testing.T) {
	f := newFake(t)
	f.tokenFails = true
	fwd, _, _, logBuf := setup(t, f)
	_, err := fwd.Do(context.Background(), false, "GET", "/x", "", nil)
	if err != ErrTokenRejected {
		t.Fatalf("err = %v", err)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, `"outcome":"rejected"`) || !strings.Contains(logs, `"client":"read"`) {
		t.Fatalf("log = %s", logs)
	}
	for _, s := range []string{"secret detail", "read-secret-value", "read-client"} {
		if strings.Contains(logs, s) || strings.Contains(err.Error(), s) {
			t.Fatalf("%q leaked", s)
		}
	}
}

func TestTokenNeverLogged(t *testing.T) {
	f := newFake(t)
	fwd, _, _, logBuf := setup(t, f)
	if _, err := fwd.Do(context.Background(), true, "GET", "/x", "", nil); err != nil {
		t.Fatal(err)
	}
	logs := logBuf.String()
	if strings.Contains(logs, "upstream-token") || strings.Contains(logs, "write-secret-value") {
		t.Fatalf("log leaks a credential: %s", logs)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs)), &line); err != nil {
		t.Fatal(err)
	}
	if line["client"] != "write" || line["outcome"] != "ok" || line["instance"] == "" || line["time"] == "" {
		t.Fatalf("token_fetch line = %v", line)
	}
}

func TestResponseCap(t *testing.T) {
	f := newFake(t)
	f.apiBody = strings.Repeat("x", 2<<20)
	fwd, _, _, _ := setup(t, f)
	if _, err := fwd.Do(context.Background(), false, "GET", "/x", "", nil); err != ErrResponseTooLarge {
		t.Fatalf("err = %v", err)
	}
}

func TestNoRedirectFollowed(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path == "/token" {
			fmt.Fprint(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	ri, rs := writeCreds(t, "a", "b")
	hc := NewHTTPClient(5 * time.Second)
	fwd := NewForwarder(srv.URL, hc, NewTokenSource("read", ri, rs, srv.URL+"/token", hc, audit.New(io.Discard)), nil, 1<<20)
	res, err := fwd.Do(context.Background(), false, "GET", "/x", "", nil)
	if err != nil || res.Status != http.StatusFound || hits != 2 {
		t.Fatalf("%v %v hits=%d", res, err, hits)
	}
}

func TestMissingWriteClient(t *testing.T) {
	f := newFake(t)
	ri, rs := writeCreds(t, "a", "b")
	hc := NewHTTPClient(5 * time.Second)
	fwd := NewForwarder(f.srv.URL, hc, NewTokenSource("read", ri, rs, f.srv.URL+"/oauth/token", hc, audit.New(io.Discard)), nil, 1<<20)
	if _, err := fwd.Do(context.Background(), true, "GET", "/x", "", nil); err != ErrToken {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckFiles(t *testing.T) {
	ri, rs := writeCreds(t, "a", "b")
	if err := NewTokenSource("read", ri, rs, "", nil, nil).CheckFiles(); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, []byte("  \n"), 0o600)
	if err := NewTokenSource("read", ri, empty, "", nil, nil).CheckFiles(); err == nil {
		t.Fatal("empty secret file accepted")
	}
	if err := NewTokenSource("read", "/nonexistent", rs, "", nil, nil).CheckFiles(); err == nil {
		t.Fatal("missing id file accepted")
	}
}
