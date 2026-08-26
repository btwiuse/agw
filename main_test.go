package agw

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name string
		auth *Authorization
		want string
	}{
		{"none", &Authorization{Type: "none"}, ""},
		{"basic credentials", &Authorization{Type: "basic", Value: "user:pass"}, "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))},
		{"basic encoded", &Authorization{Type: "basic", Value: "abc"}, "Basic abc"},
		{"bearer", &Authorization{Type: "bearer", Value: "secret"}, "Bearer secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authorizationHeader(tt.auth)
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestProxyRetriesAndInjectsAuthorization(t *testing.T) {
	var logs bytes.Buffer
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Basic dXNlcjpwYXNz" {
			t.Errorf("first authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":{"message":"Invalid URL (GET /v1/asdfasf)"}}`))
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer backup" {
			t.Errorf("second authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "payload" {
			t.Errorf("body = %q", body)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("ok"))
	}))
	defer second.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{
			{URL: first.URL, Authorization: &Authorization{Type: "basic", Value: "user:pass"}},
			{URL: second.URL, Authorization: &Authorization{Type: "bearer", Value: "backup"}},
		},
		Client: http.DefaultClient,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	req := httptest.NewRequest(http.MethodPost, "/test?x=1", strings.NewReader("payload"))
	req.Header.Set("Authorization", "Bearer client-must-not-win")
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated || recorder.Body.String() != "ok" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(logs.String(), `"msg":"upstream response"`) || !strings.Contains(logs.String(), `"status":"502 Bad Gateway"`) || !strings.Contains(logs.String(), "Invalid URL (GET /v1/asdfasf)") {
		t.Fatalf("error response was not logged: %q", logs.String())
	}
}

func TestUpstreamRequestURLPreservesClientPath(t *testing.T) {
	got, err := upstreamRequestURL("https://example.com/v1", "/v1/chat/completions?stream=true")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.com/v1/chat/completions?stream=true"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNonePreservesClientAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer from-client" {
			t.Errorf("authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{{URL: server.URL, Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer from-client")
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("response status = %d", recorder.Code)
	}
}

func TestProxyForwardsCustomMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PURGE" {
			t.Errorf("method = %q", r.Method)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{{URL: server.URL, Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	req := httptest.NewRequest("PURGE", "/resource", strings.NewReader("payload"))
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("response status = %d", recorder.Code)
	}
}

func TestCORSPreflight(t *testing.T) {
	proxy := &Proxy{
		Upstreams: []Upstream{{URL: "https://example.com", Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	req := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	req.Header.Set("Access-Control-Request-Method", "PURGE")
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("response status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("allow origin = %q", got)
	}
}

func TestCORSHeadersAreNotDuplicated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "https://upstream.example")
		w.Header().Add("Access-Control-Allow-Origin", "https://another.example")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{{URL: server.URL, Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/resource", nil))

	if got := recorder.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("allow origin = %q", got)
	}
}

func TestProxyRequestsUncompressedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("accept encoding = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{{URL: server.URL, Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/resource", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("response status = %d", recorder.Code)
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	if err := Run([]string{"-unknown"}); err == nil {
		t.Fatal("Run accepted an unknown flag")
	}
}

func TestDefaultHTTPClientHasNoOverallTimeout(t *testing.T) {
	if got := newHTTPClient(0, nil).Timeout; got != 0 {
		t.Fatalf("default timeout = %s, want 0", got)
	}
	if got := newHTTPClient(2*time.Minute, nil).Timeout; got != 2*time.Minute {
		t.Fatalf("configured timeout = %s", got)
	}
}

func TestParseSettingsSupportsLegacyAndObjectFormats(t *testing.T) {
	legacy, err := parseSettings([]byte("- url: https://example.com/v1\n  authorization:\n    type: none\n"))
	if err != nil || len(legacy.Upstreams) != 1 || legacy.Debug {
		t.Fatalf("legacy settings = %#v, error = %v", legacy, err)
	}

	modern, err := parseSettings([]byte("debug: true\nupstreams:\n- url: https://example.com/v1\n  authorization:\n    type: bearer\n    value: token\n"))
	if err != nil || !modern.Debug || len(modern.Upstreams) != 1 {
		t.Fatalf("modern settings = %#v, error = %v", modern, err)
	}
}

func TestAppSelectorRoutesOnlyCompatibleUpstreams(t *testing.T) {
	selectors := []AppSelector{
		{Name: "codex-luna", Match: AppSelectorMatch{Headers: []HeaderMatch{{Name: "User-Agent", Operator: "contains", Value: "Codex"}}}},
		{Name: "default"},
	}
	upstreams := []Upstream{
		{Name: "d1v-primary", AppSelectors: []string{"codex-luna"}},
		{Name: "deepseek", AppSelectors: []string{"default"}},
		{Name: "d1v-backup", AppSelectors: []string{"codex-luna"}},
	}
	request := http.Header{"User-Agent": []string{"Codex/1.0"}}
	routed, selected, err := routeUpstreams(upstreams, selectors, "POST", "/v1/chat/completions", nil, request, nil)
	if err != nil || selected != "codex-luna" || len(routed) != 2 {
		t.Fatalf("routed upstreams = %#v, selector=%q, error=%v", routed, selected, err)
	}
	if routed[0].Index != 0 || routed[1].Index != 2 {
		t.Fatalf("non-compatible upstream entered retry chain: %#v", routed)
	}

	routed, selected, err = routeUpstreams(upstreams, selectors, "POST", "/v1/chat/completions", nil, http.Header{"User-Agent": []string{"OpenAI/1.0"}}, nil)
	if err != nil || selected != "default" || len(routed) != 1 || routed[0].Upstream.Name != "deepseek" {
		t.Fatalf("default route = %#v, selector=%q, error=%v", routed, selected, err)
	}
}

func TestBodySelectorRoutesByModelField(t *testing.T) {
	selectors := []AppSelector{
		{Name: "deepseek-model", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "model", Operator: "exact", Value: "deepseek"}}}},
		{Name: "default"},
	}
	upstreams := []Upstream{
		{Name: "deepseek", AppSelectors: []string{"deepseek-model"}},
		{Name: "luna", AppSelectors: []string{"default"}},
	}
	routed, selected, err := routeUpstreams(upstreams, selectors, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"model":"deepseek","messages":[]}`))
	if err != nil || selected != "deepseek-model" || len(routed) != 1 || routed[0].Upstream.Name != "deepseek" {
		t.Fatalf("routed upstreams = %#v, selector=%q, error=%v", routed, selected, err)
	}

	routed, selected, err = routeUpstreams(upstreams, selectors, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"model":"gpt-5.6-luna","messages":[]}`))
	if err != nil || selected != "default" || len(routed) != 1 || routed[0].Upstream.Name != "luna" {
		t.Fatalf("default route = %#v, selector=%q, error=%v", routed, selected, err)
	}
}

func TestBodySelectorNestedFieldPrefixAndCase(t *testing.T) {
	selector := AppSelector{Name: "ds", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "metadata.provider", Operator: "prefix", Value: "Deep"}}}}
	if !appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"model":"x","metadata":{"provider":"deepseek"}}`)) {
		t.Fatal("nested case-insensitive prefix should match")
	}
	if appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"model":"x","metadata":{"provider":"openai"}}`)) {
		t.Fatal("prefix rule matched an unrelated value")
	}
	if appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`not json`)) {
		t.Fatal("non-JSON body must not match")
	}
	if appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"metadata":42}`)) {
		t.Fatal("missing nested field must not match")
	}
	if appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"metadata":{"provider":null}}`)) {
		t.Fatal("null value must not match")
	}
}

func TestBodySelectorPresentAndValidation(t *testing.T) {
	selector := AppSelector{Name: "stream", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "stream", Operator: "present"}}}}
	if !appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"stream":true}`)) {
		t.Fatal("present rule should match when field exists")
	}
	if appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, []byte(`{"model":"x"}`)) {
		t.Fatal("present rule matched a missing field")
	}
	_, err := parseSettings([]byte(`appSelectors:
  - name: invalid
    match:
      body:
        - field: model
          operator: regex
          value: "["
upstreams:
  - url: https://example.com
    appSelectors: [invalid]
`))
	if err == nil || !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("invalid body regex error = %v", err)
	}
}

func TestAppSelectorMethodFilter(t *testing.T) {
	selector := AppSelector{Name: "write", Methods: []string{"POST", "PUT"}}
	if !appSelectorMatches(selector, "post", "/v1/chat/completions", nil, http.Header{}, nil) {
		t.Fatal("lowercase request method must match case-insensitively")
	}
	if !appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{}, nil) {
		t.Fatal("configured method must match")
	}
	if appSelectorMatches(selector, "GET", "/v1/chat/completions", nil, http.Header{}, nil) {
		t.Fatal("unconfigured method must not match")
	}
	if !appSelectorMatches(AppSelector{Name: "any"}, "GET", "/v1/chat/completions", nil, http.Header{}, nil) {
		t.Fatal("selector without methods must match any method")
	}

	settings := Settings{
		AppSelectors: []AppSelector{{Name: "s", Methods: []string{"post"}}},
		Upstreams:    []Upstream{{URL: "https://example.com"}},
	}
	if err := validateSettings(&settings); err != nil {
		t.Fatal(err)
	}
	if settings.AppSelectors[0].Methods[0] != "POST" {
		t.Fatalf("method not normalized: %#v", settings.AppSelectors[0].Methods)
	}
	settings.AppSelectors[0].Methods = []string{"POST PUT"}
	if err := validateSettings(&settings); err == nil {
		t.Fatal("invalid method token must be rejected")
	}
}

func TestProxyRoutesByJSONBodyAndForwardsBody(t *testing.T) {
	deepseek := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"hi"}]}` {
			t.Errorf("body not forwarded intact: %q", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "deepseek response")
	}))
	defer deepseek.Close()
	luna := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("luna upstream received a deepseek-routed request")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer luna.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{
			{Name: "ds", URL: deepseek.URL, AppSelectors: []string{"ds-model"}, Authorization: &Authorization{Type: "none"}},
			{Name: "luna", URL: luna.URL, AppSelectors: []string{"luna-model"}, Authorization: &Authorization{Type: "none"}},
		},
		AppSelectors: []AppSelector{
			{Name: "ds-model", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "model", Operator: "prefix", Value: "deepseek"}}}},
			{Name: "luna-model", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "model", Operator: "prefix", Value: "gpt"}}}},
		},
		Client: http.DefaultClient,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"hi"}]}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "deepseek response" {
		t.Fatalf("routed response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestApplyRewritesSetsAndCreatesFields(t *testing.T) {
	got := applyRewrites([]byte(`{"model":"deepseek","messages":[]}`), []FieldRewrite{
		{Field: "model", Value: "gpt-5.6-luna"},
		{Field: "stream", Value: "true"},
		{Field: "temperature", Value: "0.5"},
		{Field: "metadata.provider", Value: "openai"},
	})
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v\n%s", err, got)
	}
	if doc["model"] != "gpt-5.6-luna" {
		t.Fatalf("model = %#v", doc["model"])
	}
	if doc["stream"] != true {
		t.Fatalf("stream = %#v", doc["stream"])
	}
	if doc["temperature"] != 0.5 {
		t.Fatalf("temperature = %#v", doc["temperature"])
	}
	metadata, ok := doc["metadata"].(map[string]any)
	if !ok || metadata["provider"] != "openai" {
		t.Fatalf("nested metadata = %#v", doc["metadata"])
	}
}

func TestApplyRewritesDisabledRulesPassThrough(t *testing.T) {
	disabled := false
	body := []byte(`{"model": "gpt-4o", "messages": []}`)
	got := applyRewrites(body, []FieldRewrite{{Field: "model", Value: "deepseek-v4-flash", Enabled: &disabled}})
	if !bytes.Equal(got, body) {
		t.Fatalf("disabled rewrite must pass the body through untouched, got %q", got)
	}
}

func TestDisabledRewriteDoesNotLog(t *testing.T) {
	disabled := false
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	selectors := []AppSelector{{Name: "codex", Rewrite: []FieldRewrite{{Field: "model", Value: "deepseek-v4-flash", Enabled: &disabled}}}}
	body := []byte(`{"model": "gpt-4o", "messages": []}`)
	got := applySelectorRewrites(body, selectors, "codex", logger, nil)
	if !bytes.Equal(got, body) {
		t.Fatalf("disabled rewrite must not change the body, got %q", got)
	}
	if strings.Contains(logs.String(), "request body rewritten") {
		t.Fatalf("disabled rewrite must not log: %q", logs.String())
	}
}

func TestApplyRewritesPreservesKeyOrder(t *testing.T) {
	body := []byte(`{"model":"deepseek","z":1,"a":{"b":2,"c":3},"m":[1,2]}`)
	got := string(applyRewrites(body, []FieldRewrite{{Field: "model", Value: "gpt"}}))
	if got != `{"model":"gpt","z":1,"a":{"b":2,"c":3},"m":[1,2]}` {
		t.Fatalf("key order was not preserved: %s", got)
	}

	// A new key is appended at the end, not alphabetically inserted.
	got = string(applyRewrites([]byte(`{"z":1,"a":2}`), []FieldRewrite{{Field: "model", Value: "gpt"}}))
	if got != `{"z":1,"a":2,"model":"gpt"}` {
		t.Fatalf("new key was not appended at the end: %s", got)
	}

	// Nested objects keep their order too, and intermediate objects are created.
	got = string(applyRewrites([]byte(`{"z":{"y":1,"x":2}}`), []FieldRewrite{{Field: "z.n", Value: "three"}}))
	if got != `{"z":{"y":1,"x":2,"n":"three"}}` {
		t.Fatalf("nested key order was not preserved: %s", got)
	}
}

func TestApplyRewritesLeavesNonObjectBodiesAlone(t *testing.T) {
	rewrites := []FieldRewrite{{Field: "model", Value: "x"}}
	if got := string(applyRewrites([]byte(`[{"model":"a"}]`), rewrites)); got != `[{"model":"a"}]` {
		t.Fatalf("array root was rewritten: %s", got)
	}
	if got := string(applyRewrites([]byte(`not json`), rewrites)); got != `not json` {
		t.Fatalf("non-JSON body was rewritten: %s", got)
	}
	if got := string(applyRewrites([]byte(`{"model":`), rewrites)); got != `{"model":` {
		t.Fatalf("malformed JSON body was rewritten: %s", got)
	}
	if got := string(applyRewrites([]byte(`{"model":"a"}`), nil)); got != `{"model":"a"}` {
		t.Fatalf("empty rewrites changed the body: %s", got)
	}
}

func TestProxyRewritesBodyBeforeForwarding(t *testing.T) {
	var rewrittenBody []byte
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rewrittenBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("rewritten body is not valid JSON: %v", err)
		}
		if doc["model"] != "gpt-5.6-luna" || doc["stream"] != true {
			t.Errorf("upstream received unrewritten body: %s", body)
		}
		if _, ok := doc["messages"]; !ok {
			t.Errorf("original fields missing after rewrite: %s", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "rewritten ok")
	}))
	defer backup.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{
			{Name: "ds-primary", URL: primary.URL, AppSelectors: []string{"ds"}, Authorization: &Authorization{Type: "none"}},
			{Name: "ds-backup", URL: backup.URL, AppSelectors: []string{"ds"}, Authorization: &Authorization{Type: "none"}},
		},
		AppSelectors: []AppSelector{
			{Name: "ds", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "model", Operator: "prefix", Value: "deepseek"}}}, Rewrite: []FieldRewrite{{Field: "model", Value: "gpt-5.6-luna"}, {Field: "stream", Value: "true"}}},
		},
		Client: http.DefaultClient,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"hi"}],"stream":false}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "rewritten ok" {
		t.Fatalf("routed response = %d %q", recorder.Code, recorder.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rewrittenBody, &doc); err != nil {
		t.Fatalf("retried body is not valid JSON: %v", err)
	}
	if doc["model"] != "gpt-5.6-luna" {
		t.Fatalf("retry attempt received unrewritten body: %s", rewrittenBody)
	}
}

func TestRewriteValidationRejectsEmptyField(t *testing.T) {
	_, err := parseSettings([]byte(`appSelectors:
  - name: invalid
    rewrite:
      - field: ""
        value: gpt-5.6-luna
upstreams:
  - url: https://example.com
    appSelectors: [invalid]
`))
	if err == nil || !strings.Contains(err.Error(), "rewrite rule") {
		t.Fatalf("empty rewrite field error = %v", err)
	}
}

func TestHeaderMatchCaseSensitivityAndRegex(t *testing.T) {
	headers := http.Header{"User-Agent": []string{"Codex/1.0"}}
	if !headerMatchMatches(HeaderMatch{Name: "User-Agent", Operator: "exact", Value: "codex/1.0"}, headers) {
		t.Fatal("exact match should be case-insensitive by default")
	}
	if headerMatchMatches(HeaderMatch{Name: "User-Agent", Operator: "exact", Value: "codex/1.0", CaseSensitive: true}, headers) {
		t.Fatal("case-sensitive exact match accepted a different case")
	}
	if !headerMatchMatches(HeaderMatch{Name: "User-Agent", Operator: "regex", Value: `^codex/[0-9]+\.[0-9]+$`}, headers) {
		t.Fatal("regex match should be case-insensitive by default")
	}
	if headerMatchMatches(HeaderMatch{Name: "User-Agent", Operator: "regex", Value: `^codex/[0-9]+\.[0-9]+$`, CaseSensitive: true}, headers) {
		t.Fatal("case-sensitive regex accepted a different case")
	}
	_, err := parseSettings([]byte(`appSelectors:
  - name: invalid
    match:
      headers:
        - name: User-Agent
          operator: regex
          value: "["
upstreams:
  - url: https://example.com
    appSelectors: [invalid]
`))
	if err == nil || !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("invalid regex error = %v", err)
	}
}

func TestAppSelectorWithoutRulesMatchesAllRequests(t *testing.T) {
	selector := AppSelector{Name: "catch-all"}
	if !appSelectorMatches(selector, "POST", "/v1/chat/completions", nil, http.Header{"User-Agent": []string{"Codex/1.0"}}, nil) {
		t.Fatal("AppSelector without header rules should match every request")
	}
}

func TestPathSelectorRoutesByAPI(t *testing.T) {
	selectors := []AppSelector{
		{Name: "anthropic-messages", Match: AppSelectorMatch{Path: []PathMatch{{Operator: "exact", Value: "/v1/messages"}}}},
		{Name: "chat-completions", Match: AppSelectorMatch{Path: []PathMatch{{Operator: "exact", Value: "/v1/chat/completions"}}}},
		{Name: "responses-api", Match: AppSelectorMatch{Path: []PathMatch{{Operator: "exact", Value: "/v1/responses"}}}},
	}
	upstreams := []Upstream{
		{Name: "anthropic", AppSelectors: []string{"anthropic-messages"}},
		{Name: "openai", AppSelectors: []string{"responses-api"}},
		{Name: "deepseek", AppSelectors: []string{"chat-completions"}},
		{Name: "openai-chat", AppSelectors: []string{"chat-completions", "responses-api"}},
	}

	tests := []struct {
		path     string
		selector string
		want     []string
	}{
		{"/v1/messages", "anthropic-messages", []string{"anthropic"}},
		{"/v1/chat/completions", "chat-completions", []string{"deepseek", "openai-chat"}},
		{"/v1/responses", "responses-api", []string{"openai", "openai-chat"}},
	}
	for _, tt := range tests {
		routed, selected, err := routeUpstreams(upstreams, selectors, "POST", tt.path, nil, http.Header{}, nil)
		if err != nil || selected != tt.selector {
			t.Fatalf("path %s: routed=%#v selector=%q error=%v", tt.path, routed, selected, err)
		}
		got := make([]string, 0, len(routed))
		for _, r := range routed {
			got = append(got, r.Upstream.Name)
		}
		if len(got) != len(tt.want) {
			t.Fatalf("path %s: routed %v, want %v", tt.path, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("path %s: routed %v, want %v", tt.path, got, tt.want)
			}
		}
	}

	if _, _, err := routeUpstreams(upstreams, selectors, "POST", "/v1/embeddings", nil, http.Header{}, nil); err == nil {
		t.Fatal("unmatched path should fail routing")
	}
}

func TestPathMatchSemantics(t *testing.T) {
	rule := func(op, value string) PathMatch { return PathMatch{Operator: op, Value: value} }
	if !pathMatchMatches(rule("exact", "/v1/chat/completions"), "/v1/chat/completions") {
		t.Fatal("exact match should succeed")
	}
	if pathMatchMatches(rule("exact", "/v1/chat/completions"), "/v1/CHAT/completions") {
		t.Fatal("path matching must be case-sensitive")
	}
	if !pathMatchMatches(rule("prefix", "/v1/"), "/v1/responses") {
		t.Fatal("prefix match should succeed")
	}
	if !pathMatchMatches(rule("contains", "responses"), "/v1/responses") {
		t.Fatal("contains match should succeed")
	}
	if !pathMatchMatches(rule("regex", `^/v1/(responses|messages)$`), "/v1/messages") {
		t.Fatal("regex match should succeed")
	}
	if pathMatchMatches(rule("regex", "["), "/v1/chat/completions") {
		t.Fatal("invalid regex must not match")
	}
	if !pathMatchMatches(rule("present", ""), "/anything") {
		t.Fatal("present rule should always match a path")
	}
}

func TestQueryMatchSemantics(t *testing.T) {
	rule := func(name, op, value string) QueryMatch { return QueryMatch{Name: name, Operator: op, Value: value} }
	query := url.Values{"model": []string{"deepseek-v4"}, "api-version": []string{"2024-02-15"}}
	if !queryMatchMatches(rule("model", "exact", "deepseek-v4"), query) {
		t.Fatal("exact query match should succeed")
	}
	if !queryMatchMatches(rule("model", "prefix", "deepseek"), query) {
		t.Fatal("prefix query match should succeed")
	}
	if !queryMatchMatches(rule("model", "exact", "DEEPSEEK-V4"), query) {
		t.Fatal("query matching must be case-insensitive by default")
	}
	if !queryMatchMatches(QueryMatch{Name: "model", Operator: "exact", Value: "deepseek-v4", CaseSensitive: true}, query) {
		t.Fatal("caseSensitive query match should succeed")
	}
	if queryMatchMatches(QueryMatch{Name: "model", Operator: "exact", Value: "deepseek-V4", CaseSensitive: true}, query) {
		t.Fatal("caseSensitive query match must not ignore case differences")
	}
	if !queryMatchMatches(rule("model", "regex", `^deepseek-v\d+$`), query) {
		t.Fatal("regex query match should succeed")
	}
	if queryMatchMatches(rule("model", "regex", "["), query) {
		t.Fatal("invalid regex must not match")
	}
	if !queryMatchMatches(rule("api-version", "present", ""), query) {
		t.Fatal("present rule should match an existing query parameter")
	}
	if queryMatchMatches(rule("missing", "present", ""), query) {
		t.Fatal("present rule must not match a missing query parameter")
	}
}

func TestQuerySelectorRoutesByParam(t *testing.T) {
	selectors := []AppSelector{
		{Name: "by-version", Match: AppSelectorMatch{Query: []QueryMatch{{Name: "api-version", Operator: "prefix", Value: "2024"}}}},
		{Name: "by-model", Match: AppSelectorMatch{Query: []QueryMatch{{Name: "model", Operator: "exact", Value: "deepseek"}}}},
		{Name: "default"},
	}
	upstreams := []Upstream{
		{Name: "v2024", AppSelectors: []string{"by-version"}},
		{Name: "deepseek", AppSelectors: []string{"by-model"}},
		{Name: "fallback", AppSelectors: []string{"default"}},
	}

	routed, selected, err := routeUpstreams(upstreams, selectors, "POST", "/v1/chat/completions", url.Values{"api-version": []string{"2024-02-15"}}, http.Header{}, nil)
	if err != nil || selected != "by-version" || len(routed) != 1 || routed[0].Upstream.Name != "v2024" {
		t.Fatalf("version route = %#v selector=%q error=%v", routed, selected, err)
	}
	routed, selected, err = routeUpstreams(upstreams, selectors, "POST", "/v1/chat/completions", url.Values{"model": []string{"deepseek"}}, http.Header{}, nil)
	if err != nil || selected != "by-model" || len(routed) != 1 || routed[0].Upstream.Name != "deepseek" {
		t.Fatalf("model route = %#v selector=%q error=%v", routed, selected, err)
	}
	routed, selected, err = routeUpstreams(upstreams, selectors, "POST", "/v1/chat/completions", url.Values{}, http.Header{}, nil)
	if err != nil || selected != "default" || len(routed) != 1 || routed[0].Upstream.Name != "fallback" {
		t.Fatalf("default route = %#v selector=%q error=%v", routed, selected, err)
	}
}

func TestPathSelectorValidation(t *testing.T) {
	configs := []string{
		`appSelectors:
  - name: bad-op
    match:
      path:
        - operator: fuzzy
          value: /v1
upstreams:
  - url: https://example.com
    appSelectors: [bad-op]
`,
		`appSelectors:
  - name: empty-value
    match:
      path:
        - operator: exact
upstreams:
  - url: https://example.com
    appSelectors: [empty-value]
`,
		`appSelectors:
  - name: bad-regex
    match:
      path:
        - operator: regex
          value: "["
upstreams:
  - url: https://example.com
    appSelectors: [bad-regex]
`,
	}
	for _, config := range configs {
		if _, err := parseSettings([]byte(config)); err == nil {
			t.Fatalf("config should fail validation: %s", config)
		}
	}
}

func TestQuerySelectorValidation(t *testing.T) {
	configs := []string{
		`appSelectors:
  - name: empty-name
    match:
      query:
        - name: ""
          operator: exact
          value: x
upstreams:
  - url: https://example.com
    appSelectors: [empty-name]
`,
		`appSelectors:
  - name: bad-op
    match:
      query:
        - name: model
          operator: fuzzy
          value: deepseek
upstreams:
  - url: https://example.com
    appSelectors: [bad-op]
`,
		`appSelectors:
  - name: bad-regex
    match:
      query:
        - name: model
          operator: regex
          value: "["
upstreams:
  - url: https://example.com
    appSelectors: [bad-regex]
`,
	}
	for _, config := range configs {
		if _, err := parseSettings([]byte(config)); err == nil {
			t.Fatalf("config should fail validation: %s", config)
		}
	}
}

func TestDisabledRulesAreSkipped(t *testing.T) {
	disabled := false
	enabled := true

	// Header, body and path rules that are disabled must not block routing.
	selector := AppSelector{
		Name: "mixed",
		Match: AppSelectorMatch{
			Path:    []PathMatch{{Operator: "exact", Value: "/v1/chat/completions", Enabled: &disabled}},
			Query:   []QueryMatch{{Name: "model", Operator: "exact", Value: "blocked", Enabled: &disabled}},
			Headers: []HeaderMatch{{Name: "User-Agent", Operator: "contains", Value: "never-matches", Enabled: &disabled}},
			Body:    []BodyMatch{{Field: "model", Operator: "exact", Value: "blocked", Enabled: &disabled}},
		},
	}
	if !appSelectorMatches(selector, "POST", "/v1/chat/completions", url.Values{"model": []string{"blocked"}}, http.Header{"User-Agent": []string{"Codex/1.0"}}, []byte(`{"model":"blocked"}`)) {
		t.Fatal("disabled rules must not block a selector")
	}

	// Enabled rules still apply.
	selector.Match.Headers[0].Enabled = &enabled
	if appSelectorMatches(selector, "POST", "/v1/chat/completions", url.Values{"model": []string{"blocked"}}, http.Header{"User-Agent": []string{"Codex/1.0"}}, []byte(`{"model":"blocked"}`)) {
		t.Fatal("enabled header rule should still block a non-matching request")
	}
	selector.Match.Headers[0].Enabled = &disabled
	selector.Match.Query[0].Enabled = &enabled
	if appSelectorMatches(selector, "POST", "/v1/chat/completions", url.Values{"model": []string{"other"}}, http.Header{"User-Agent": []string{"Codex/1.0"}}, []byte(`{"model":"blocked"}`)) {
		t.Fatal("enabled query rule should still block a non-matching request")
	}

	// Disabled rewrites must not rewrite the body.
	rewritten := applyRewrites([]byte(`{"model":"deepseek","messages":[]}`), []FieldRewrite{{Field: "model", Value: "gpt", Enabled: &disabled}})
	if strings.Contains(string(rewritten), "gpt") {
		t.Fatalf("disabled rewrite modified the body: %s", rewritten)
	}
	rewritten = applyRewrites([]byte(`{"model":"deepseek","messages":[]}`), []FieldRewrite{{Field: "model", Value: "gpt", Enabled: &enabled}})
	if !strings.Contains(string(rewritten), `"model":"gpt"`) {
		t.Fatalf("enabled rewrite did not apply: %s", rewritten)
	}
}

func TestDisabledRulesSkipValidation(t *testing.T) {
	settings, err := parseSettings([]byte(`appSelectors:
  - name: messy
    match:
      path:
        - operator: regex
          value: "["
          enabled: false
      headers:
        - name: User-Agent
          operator: contains
          value: ""
upstreams:
  - url: https://example.com
    appSelectors: [messy]
`))
	if err != nil {
		t.Fatalf("disabled invalid rules should be accepted: %v", err)
	}
	if settings.AppSelectors[0].Match.Path[0].RuleEnabled() {
		t.Fatal("explicit enabled: false should disable the rule")
	}
	if !settings.AppSelectors[0].Match.Headers[0].RuleEnabled() {
		t.Fatal("rules without an enabled field default to enabled")
	}
}

func TestProxyRoutesResponsesAPIOnlyToCompatibleUpstream(t *testing.T) {
	chatOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("chat-only upstream received %s request", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "chat")
	}))
	defer chatOnly.Close()
	responses := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("responses upstream received %s request", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "responses")
	}))
	defer responses.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{
			{Name: "deepseek", URL: chatOnly.URL, AppSelectors: []string{"chat-completions"}, Authorization: &Authorization{Type: "none"}},
			{Name: "openai", URL: responses.URL, AppSelectors: []string{"responses-api"}, Authorization: &Authorization{Type: "none"}},
		},
		AppSelectors: []AppSelector{
			{Name: "chat-completions", Match: AppSelectorMatch{Path: []PathMatch{{Operator: "exact", Value: "/v1/chat/completions"}}}},
			{Name: "responses-api", Match: AppSelectorMatch{Path: []PathMatch{{Operator: "exact", Value: "/v1/responses"}}}},
		},
		Client: http.DefaultClient,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5"}`)))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "responses" {
		t.Fatalf("responses route = %d %q", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"deepseek-v4"}`)))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "chat" {
		t.Fatalf("chat route = %d %q", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unroutable path status = %d", recorder.Code)
	}
}

func TestProxyRoutesByQueryParam(t *testing.T) {
	byVersion := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "v2024")
	}))
	defer byVersion.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "fallback")
	}))
	defer fallback.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{
			{Name: "v2024", URL: byVersion.URL, AppSelectors: []string{"by-version"}, Authorization: &Authorization{Type: "none"}},
			{Name: "fallback", URL: fallback.URL, AppSelectors: []string{"default"}, Authorization: &Authorization{Type: "none"}},
		},
		AppSelectors: []AppSelector{
			{Name: "by-version", Match: AppSelectorMatch{Query: []QueryMatch{{Name: "api-version", Operator: "prefix", Value: "2024"}}}},
			{Name: "default"},
		},
		Client: http.DefaultClient,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions?api-version=2024-02-15", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "v2024" {
		t.Fatalf("query route = %d %q", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions?model=deepseek", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "fallback" {
		t.Fatalf("fallback route = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestAppSelectorValidationRejectsUnknownUpstreamReference(t *testing.T) {
	_, err := parseSettings([]byte(`appSelectors:
  - name: codex
    match:
      headers:
        - name: User-Agent
          operator: contains
          value: Codex
upstreams:
  - name: primary
    url: https://example.com
    appSelectors: [missing]
`))
	if err == nil || !strings.Contains(err.Error(), "unknown app selector") {
		t.Fatalf("unknown selector reference error = %v", err)
	}
}

func TestProxyRewritesBodyUpdatesContentLength(t *testing.T) {
	var gotContentLength int64
	var gotHeaderContentLength string
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentLength = r.ContentLength
		gotHeaderContentLength = r.Header.Get("Content-Length")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxy := &Proxy{
		Upstreams: []Upstream{
			{URL: upstream.URL, AppSelectors: []string{"rewrite"}, Authorization: &Authorization{Type: "none"}},
		},
		AppSelectors: []AppSelector{
			{
				Name:    "rewrite",
				Match:   AppSelectorMatch{Body: []BodyMatch{{Field: "model", Operator: "prefix", Value: "deepseek"}}},
				Rewrite: []FieldRewrite{{Field: "model", Value: "gpt-5.6-luna"}},
			},
		},
		Client: http.DefaultClient,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}

	original := `{"model":"deepseek","messages":[]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(original))
	request.Header.Set("Content-Type", "application/json")
	// A real server request keeps Content-Length in the header map; simulate
	// the stale length the proxy would otherwise copy verbatim.
	request.Header.Set("Content-Length", strconv.Itoa(len(original)))
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("proxy status = %d", recorder.Code)
	}
	if !strings.Contains(gotBody, `"model":"gpt-5.6-luna"`) {
		t.Fatalf("upstream body was not rewritten: %s", gotBody)
	}
	if int64(len(gotBody)) == int64(len(original)) {
		t.Fatalf("test body lengths should differ to prove the fix")
	}
	if gotContentLength != int64(len(gotBody)) {
		t.Fatalf("upstream ContentLength = %d, want %d (stale header %q)", gotContentLength, len(gotBody), gotHeaderContentLength)
	}
	if gotHeaderContentLength != strconv.Itoa(len(gotBody)) {
		t.Fatalf("upstream Content-Length header = %q, want %d", gotHeaderContentLength, len(gotBody))
	}
}

func TestProxyRetriesWithinMatchedAppSelectorOnly(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	deepseek := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("incompatible upstream received routed request")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer deepseek.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "luna backup")
	}))
	defer backup.Close()

	var logs bytes.Buffer
	proxy := &Proxy{
		Upstreams: []Upstream{
			{Name: "luna-primary", URL: primary.URL, AppSelectors: []string{"codex-luna"}, Authorization: &Authorization{Type: "none"}},
			{Name: "ds-video", URL: deepseek.URL, AppSelectors: []string{"deepseek"}, Authorization: &Authorization{Type: "none"}},
			{Name: "luna-backup", URL: backup.URL, AppSelectors: []string{"codex-luna"}, Authorization: &Authorization{Type: "none"}},
		},
		AppSelectors: []AppSelector{
			{Name: "codex-luna", Match: AppSelectorMatch{Headers: []HeaderMatch{{Name: "User-Agent", Operator: "contains", Value: "Codex"}}}},
			{Name: "deepseek", Match: AppSelectorMatch{Headers: []HeaderMatch{{Name: "User-Agent", Operator: "contains", Value: "DeepSeek"}}}},
		},
		Client: http.DefaultClient,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("payload"))
	request.Header.Set("User-Agent", "Codex/1.0")
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "luna backup" {
		t.Fatalf("routed response = %d %q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(logs.String(), `"msg":"upstream attempt"`) || !strings.Contains(logs.String(), `"upstream":"luna-backup"`) || strings.Contains(logs.String(), `"upstream":"ds-video"`) {
		t.Fatalf("retry chain crossed AppSelector boundary: %q", logs.String())
	}
}

func TestUpdateConfigChangesRuntimeSettings(t *testing.T) {
	configPath := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(configPath, []byte("debug: false\nupstreams:\n- url: https://old.example\n  authorization:\n    type: none\n"), 0600); err != nil {
		t.Fatal(err)
	}
	proxy := &Proxy{
		Upstreams:  []Upstream{{URL: "https://old.example", Authorization: &Authorization{Type: "none"}}},
		Client:     http.DefaultClient,
		Logger:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Config:     FileConfig(configPath),
		AllowDebug: true,
	}
	req := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"debug":true,"appSelectors":[{"name":"codex","match":{"headers":[{"name":"User-Agent","operator":"regex","value":"^Codex","caseSensitive":true}]}}],"upstreams":[{"url":"https://new.example","appSelectors":["codex"],"authorization":{"type":"none"}}]}`))
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("response status = %d", recorder.Code)
	}
	if !proxy.Debug || len(proxy.Upstreams) != 1 || proxy.Upstreams[0].URL != "https://new.example" || len(proxy.AppSelectors) != 1 || !proxy.AppSelectors[0].Match.Headers[0].CaseSensitive {
		t.Fatalf("runtime settings were not updated: debug=%t upstreams=%#v selectors=%#v", proxy.Debug, proxy.Upstreams, proxy.AppSelectors)
	}
	settings, err := loadSettings(FileConfig(configPath))
	if err != nil || !settings.Debug || settings.Upstreams[0].URL != "https://new.example" || !settings.AppSelectors[0].Match.Headers[0].CaseSensitive {
		t.Fatalf("saved settings = %#v, error = %v", settings, err)
	}
}

func TestUpdateConfigDebugRequiresAllowDebug(t *testing.T) {
	configPath := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(configPath, []byte("debug: true\nupstreams:\n- url: https://old.example\n  authorization:\n    type: none\n"), 0600); err != nil {
		t.Fatal(err)
	}
	proxy := &Proxy{
		Upstreams: []Upstream{{URL: "https://old.example", Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Config:    FileConfig(configPath),
		Debug:     true, // loaded from disk but --allow-debug was not passed
	}
	req := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"debug":true,"upstreams":[{"url":"https://new.example","authorization":{"type":"none"}}],"appSelectors":[]}`))
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("response status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if proxy.Debug {
		t.Fatalf("client debug change must not take effect without AllowDebug: debug=%t", proxy.Debug)
	}
	settings, err := loadSettings(FileConfig(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if settings.Debug {
		t.Fatalf("client debug change must not be persisted without AllowDebug: %#v", settings)
	}
}

func TestManagementCredentials(t *testing.T) {
	user, password, err := managementCredentials(Options{})
	if err != nil || user != "" || password != "" {
		t.Fatalf("no credentials should resolve to empty: user=%q pass=%q err=%v", user, password, err)
	}
	// Half-configured credentials must error when there is no env fallback.
	if _, _, err := managementCredentials(Options{AdminUser: "only-user"}); err == nil {
		t.Fatal("half-configured credentials must error")
	}
	if _, _, err := managementCredentials(Options{AdminPassword: "only-pass"}); err == nil {
		t.Fatal("half-configured credentials must error")
	}
	t.Setenv("AGW_ADMIN_USER", "env-user")
	t.Setenv("AGW_ADMIN_PASSWORD", "env-pass")

	user, password, err = managementCredentials(Options{AdminUser: "flag-user", AdminPassword: "flag-pass"})
	if err != nil || user != "flag-user" || password != "flag-pass" {
		t.Fatalf("flags must win over env: user=%q pass=%q err=%v", user, password, err)
	}

	user, password, err = managementCredentials(Options{})
	if err != nil || user != "env-user" || password != "env-pass" {
		t.Fatalf("env fallback failed: user=%q pass=%q err=%v", user, password, err)
	}

	// A single flag may fill in the missing env side.
	user, password, err = managementCredentials(Options{AdminUser: "flag-user"})
	if err != nil || user != "flag-user" || password != "env-pass" {
		t.Fatalf("flag+env mix failed: user=%q pass=%q err=%v", user, password, err)
	}
	user, password, err = managementCredentials(Options{AdminPassword: "flag-pass"})
	if err != nil || user != "env-user" || password != "flag-pass" {
		t.Fatalf("env+flag mix failed: user=%q pass=%q err=%v", user, password, err)
	}
}

func TestSessionHubTracksLifecycleAndRedactsHeaders(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("payload"))
	req.Header.Set("Session-Id", "session-primary")
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("X-Client-Request-Id", "request-1")

	tracked := hub.start(req)
	cards := hub.cards()
	if len(cards) != 1 || cards[0].State != "connecting" || len(cards[0].ID) != 36 || cards[0].ID[14] != '7' {
		t.Fatalf("initial cards = %#v", cards)
	}
	tracked.connected(http.StatusOK)
	requestBody := []byte(strings.Repeat("request-body-", 2048))
	tracked.setRequestBody("application/json", requestBody)
	tracked.setContentType("text/event-stream")
	tracked.captureResponse([]byte("data: hello\\n\\n"))
	tracked.complete(http.StatusOK, 2048, nil)

	cards = hub.cards()
	if cards[0].State != "completed" || cards[0].Status != "200" || cards[0].StatusClass != "status-2xx" || cards[0].Latest.Bytes != "2.0 KB" {
		t.Fatalf("completed card = %#v", cards[0])
	}
	content, err := hub.renderCards()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, "secret-token") || !strings.Contains(content, "[redacted]") {
		t.Fatalf("session card exposes a sensitive header: %s", content)
	}
	if strings.Contains(content, "data: hello") || strings.Contains(content, "request-body-") {
		t.Fatalf("session card embeds payload data: %s", content)
	}
	if !strings.Contains(content, `data-payload-open="request"`) || !strings.Contains(content, `data-payload-open="response"`) || !strings.Contains(content, "data-payload-buttons") {
		t.Fatalf("session card does not include the payload open buttons: %s", content)
	}
	if !strings.Contains(content, `<span class="session-metric session-send"><i data-lucide="arrow-up" aria-hidden="true"></i><strong>26.0 KB</strong></span>`) || !strings.Contains(content, `<span class="session-metric session-receive"><i data-lucide="arrow-down" aria-hidden="true"></i><strong>15 B</strong></span>`) {
		t.Fatalf("session card does not include the send/receive summary: %s", content)
	}
	capturedRequestBody, found, err := hub.readPayload(cards[0].ID, "request", 0)
	if err != nil || !found || !bytes.Equal(capturedRequestBody, requestBody) {
		t.Fatalf("request payload length = %d, found=%t, err=%v", len(capturedRequestBody), found, err)
	}
	responseBody, found, err := hub.readPayload(cards[0].ID, "response", 0)
	if err != nil || !found || string(responseBody) != "data: hello\\n\\n" {
		t.Fatalf("response payload = %q, found=%t, err=%v", responseBody, found, err)
	}
}

func TestSessionHubUsesSeparateServerUUIDv7s(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	first := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	second := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	first.Header.Set("Session-Id", "client-reused-session")
	second.Header.Set("Session-Id", "client-reused-session")
	hub.start(first)
	hub.start(second)

	cards := hub.cards()
	if len(cards) != 2 || cards[0].ID == cards[1].ID {
		t.Fatalf("server sessions were grouped: %#v", cards)
	}
	for _, card := range cards {
		if len(card.ID) != 36 || card.ID[14] != '7' || (card.ID[19] != '8' && card.ID[19] != '9' && card.ID[19] != 'a' && card.ID[19] != 'b') {
			t.Fatalf("session ID is not UUIDv7: %q", card.ID)
		}
	}
}

func TestProxyInterceptionPreservesSSEStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range []string{"data: first\\n\\n", "data: second\\n\\n"} {
			_, _ = io.WriteString(w, chunk)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	hub := newSessionHub()
	defer hub.close()
	proxy := &Proxy{Upstreams: []Upstream{{URL: upstream.URL, Authorization: &Authorization{Type: "none"}}}, Client: http.DefaultClient, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), Sessions: hub}
	request := httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	request.Header.Set("Session-Id", "stream-session")
	recorder := httptest.NewRecorder()
	requestLogger(proxy.Logger, proxy).ServeHTTP(recorder, request)

	want := "data: first\\n\\ndata: second\\n\\n"
	if got := recorder.Body.String(); got != want {
		t.Fatalf("client stream = %q, want %q", got, want)
	}
	cards := hub.cards()
	responseBody, found, err := hub.readPayload(cards[0].ID, "response", 0)
	if err != nil || !found || string(responseBody) != want {
		t.Fatalf("intercepted stream = %q, found=%t, err=%v", responseBody, found, err)
	}
}

func TestProxySessionCardShowsAppSelectorAndUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	hub := newSessionHub()
	defer hub.close()
	proxy := &Proxy{
		Upstreams:    []Upstream{{Name: "d1v.ai", URL: upstream.URL, AppSelectors: []string{"codex-luna"}, Authorization: &Authorization{Type: "none"}}},
		AppSelectors: []AppSelector{{Name: "codex-luna", Match: AppSelectorMatch{Headers: []HeaderMatch{{Name: "User-Agent", Operator: "contains", Value: "Codex"}}}}},
		Client:       http.DefaultClient,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Sessions:     hub,
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.6-luna","messages":[]}`))
	request.Header.Set("User-Agent", "Codex/1.0")
	requestLogger(proxy.Logger, proxy).ServeHTTP(httptest.NewRecorder(), request)

	content, err := hub.renderCards()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "codex-luna") || !strings.Contains(content, "d1v.ai") {
		t.Fatalf("session card route details missing: %s", content)
	}
	if !strings.Contains(content, `class="session-cell session-model">gpt-5.6-luna<`) {
		t.Fatalf("session card does not show the request model: %s", content)
	}
	if !strings.Contains(content, `class="session-cell session-selector">codex-luna<`) || !strings.Contains(content, `class="session-cell session-upstream">d1v.ai<`) {
		t.Fatalf("session card does not put selector/upstream in their own columns: %s", content)
	}
}

func TestSessionCardShowsRewrittenModel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	hub := newSessionHub()
	defer hub.close()
	proxy := &Proxy{
		Upstreams:    []Upstream{{URL: upstream.URL, AppSelectors: []string{"ds"}, Authorization: &Authorization{Type: "none"}}},
		AppSelectors: []AppSelector{{Name: "ds", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "model", Operator: "prefix", Value: "deepseek"}}}, Rewrite: []FieldRewrite{{Field: "model", Value: "gpt-5.6-luna"}}}},
		Client:       http.DefaultClient,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Sessions:     hub,
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"deepseek-v4-flash","messages":[]}`))
	request.Header.Set("Content-Type", "application/json")
	requestLogger(proxy.Logger, proxy).ServeHTTP(httptest.NewRecorder(), request)

	content, err := hub.renderCards()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, `class="session-cell session-model">deepseek-v4-flash =&gt; gpt-5.6-luna<`) {
		t.Fatalf("session card does not show the original => rewritten model: %s", content)
	}
	if strings.Contains(content, `class="session-cell session-model">deepseek-v4-flash<`) {
		t.Fatalf("session card hides the rewrite: %s", content)
	}
}

func TestSessionHubEvictsOldRecordsAndFiles(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	for i := 0; i < maxSessionCards+10; i++ {
		hub.start(httptest.NewRequest(http.MethodGet, "/v1/responses", nil))
	}
	hub.mu.Lock()
	count := len(hub.records)
	hub.mu.Unlock()
	if count != maxSessionCards {
		t.Fatalf("records = %d, want %d", count, maxSessionCards)
	}
	store := hub.payloads.(*filePayloadStore)
	entries, err := os.ReadDir(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > maxSessionCards*2 {
		t.Fatalf("payload files = %d, want <= %d", len(entries), maxSessionCards*2)
	}
}

func TestSessionResponsePayloadReadsLatestDiskBytes(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	request := httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	request.Header.Set("Session-Id", "preview-tail")
	tracked := hub.start(request)
	tracked.setContentType("text/event-stream")
	tracked.captureResponse([]byte(strings.Repeat("a", 128<<10) + "tail"))

	cards := hub.cards()
	payload, found, err := hub.readPayload(cards[0].ID, "response", 64<<10)
	if err != nil || !found {
		t.Fatalf("response payload found=%t, err=%v", found, err)
	}
	if got := len(payload); got != 64<<10 {
		t.Fatalf("tail length = %d, want %d", got, 64<<10)
	}
	if !strings.HasSuffix(string(payload), "tail") {
		t.Fatalf("tail does not retain latest response data")
	}
}

func TestSessionPayloadFullEndpointReturnsWholeFile(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	request := httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	tracked := hub.start(request)
	tracked.setContentType("text/plain")
	full := bytes.Repeat([]byte("x"), 100<<10)
	tracked.captureResponse(full)

	proxy := &Proxy{Sessions: hub, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	cards := hub.cards()

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/sessions/"+cards[0].ID+"/response?full=1", nil))
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), full) {
		t.Fatalf("full payload = %d bytes, want %d (status %d)", recorder.Body.Len(), len(full), recorder.Code)
	}

	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/sessions/"+cards[0].ID+"/response", nil))
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 64<<10 {
		t.Fatalf("preview tail length = %d, want %d (status %d)", recorder.Body.Len(), 64<<10, recorder.Code)
	}

	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/sessions/"+cards[0].ID+"/request?full=1", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing request file status = %d, want 404", recorder.Code)
	}
}

func TestMemoryPayloadStoreRoundTrip(t *testing.T) {
	store := MemoryPayloads()
	defer store.Close()
	file, err := store.Create("key.response")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if got := file.Size(); got != 11 {
		t.Fatalf("payload size = %d, want 11", got)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := store.Read("key.response", 0)
	if err != nil || string(data) != "hello world" {
		t.Fatalf("read = %q err=%v", data, err)
	}
	tail, err := store.Read("key.response", 5)
	if err != nil || string(tail) != "world" {
		t.Fatalf("tail = %q err=%v", tail, err)
	}
	if err := store.WriteRequest("key.request", []byte("req")); err != nil {
		t.Fatal(err)
	}
	req, err := store.Read("key.request", 0)
	if err != nil || string(req) != "req" {
		t.Fatalf("request = %q err=%v", req, err)
	}
	if err := store.Remove("key.response"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("key.response", 0); err == nil {
		t.Fatal("removed payload must not be readable")
	}
}

func TestMemoryConfigStore(t *testing.T) {
	store := MemoryConfig()
	config := "debug: true\nupstreams:\n- url: https://example.com\n  authorization:\n    type: none\n"
	if err := store.Write([]byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err := loadSettings(store)
	if err != nil || !settings.Debug || len(settings.Upstreams) != 1 {
		t.Fatalf("memory config settings = %#v err=%v", settings, err)
	}
}

func TestEnsureConfigCreatesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	created, err := ensureConfig(path)
	if err != nil || !created {
		t.Fatalf("ensureConfig = %v, %v", created, err)
	}
	settings, err := loadSettings(FileConfig(path))
	if err != nil || len(settings.Upstreams) != 1 || settings.Upstreams[0].URL != "https://example.com/v1" {
		t.Fatalf("created config does not load: %#v err=%v", settings, err)
	}
	created, err = ensureConfig(path)
	if err != nil || created {
		t.Fatalf("second ensureConfig should not rewrite: %v, %v", created, err)
	}
}

func TestSessionHubWithMemoryPayloads(t *testing.T) {
	hub := newSessionHubWith(MemoryPayloads())
	defer hub.close()
	request := httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	tracked := hub.start(request)
	body := []byte(`{"model":"deepseek"}`)
	tracked.setRequestBody("application/json", body)
	tracked.setContentType("text/plain")
	tracked.captureResponse([]byte("chunk1"))
	tracked.captureResponse([]byte("chunk2"))
	tracked.complete(200, 12, nil)

	record := hub.records[tracked.sessionID]
	latest := record.Requests[len(record.Requests)-1]
	if latest.RequestBytes != int64(len(body)) || latest.ResponseBytes != 12 {
		t.Fatalf("bytes not tracked: req=%d resp=%d", latest.RequestBytes, latest.ResponseBytes)
	}
	data, found, err := hub.readPayload(tracked.sessionID, "response", 0)
	if err != nil || !found || string(data) != "chunk1chunk2" {
		t.Fatalf("response payload = %q found=%t err=%v", data, found, err)
	}
}

func TestSessionPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	hub := newSessionHubPersistent(dir)
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	tracked := hub.start(request)
	body := []byte(`{"model":"deepseek"}`)
	tracked.setRequestBody("application/json", body)
	tracked.setContentType("text/plain")
	tracked.captureResponse([]byte("chunk-one"))
	tracked.captureResponse([]byte("chunk-two"))
	tracked.complete(200, 12, nil)
	sessionID := tracked.sessionID
	hub.close()

	restarted := newSessionHubPersistent(dir)
	defer restarted.close()
	record, ok := restarted.records[sessionID]
	if !ok || len(record.Requests) != 1 {
		t.Fatalf("record not restored: %#v", record)
	}
	latest := record.Requests[len(record.Requests)-1]
	if latest.State != "completed" || latest.ResponsePayload != nil {
		t.Fatalf("restored request state = %q payload=%v", latest.State, latest.ResponsePayload)
	}
	data, found, err := restarted.readPayload(sessionID, "response", 0)
	if err != nil || !found || string(data) != "chunk-onechunk-two" {
		t.Fatalf("response payload after restart = %q found=%t err=%v", data, found, err)
	}
	reqData, found, err := restarted.readPayload(sessionID, "request", 0)
	if err != nil || !found || !bytes.Equal(reqData, body) {
		t.Fatalf("request payload after restart = %q found=%t err=%v", reqData, found, err)
	}
}

func TestLogHubPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	hub := newLogHubPersistent(dir)
	for i := 0; i < 3; i++ {
		if _, err := hub.Write([]byte(fmt.Sprintf("line-%d\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	hub.close()

	restarted := newLogHubPersistent(dir)
	defer restarted.close()
	_, history := restarted.subscribe()
	if len(history) != 3 || history[0] != "line-0" || history[2] != "line-2" {
		t.Fatalf("restored history = %#v", history)
	}
	if _, err := restarted.Write([]byte("line-3\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dir + "/logs.jsonl")
	if err != nil || !strings.Contains(string(data), "line-3") {
		t.Fatalf("appended log file = %q err=%v", data, err)
	}
}

func TestLogHubPersistentHistoryNotTruncatedTo100(t *testing.T) {
	dir := t.TempDir()
	hub := newLogHubPersistent(dir)
	for i := 0; i < 150; i++ {
		if _, err := hub.Write([]byte(fmt.Sprintf("line-%d\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	hub.close()

	restarted := newLogHubPersistent(dir)
	defer restarted.close()
	_, history := restarted.subscribe()
	if len(history) != 150 || history[0] != "line-0" || history[149] != "line-149" {
		t.Fatalf("persistent history was truncated to %d lines", len(history))
	}
}

func TestLogHubMemoryHistoryCapped(t *testing.T) {
	hub := newLogHub()
	for i := 0; i < 150; i++ {
		_, _ = hub.Write([]byte(fmt.Sprintf("line-%d\n", i)))
	}
	_, history := hub.subscribe()
	if len(history) != 100 || history[0] != "line-50" {
		t.Fatalf("in-memory history = %d lines, first=%q", len(history), history[0])
	}
}

func TestRecoverJSONLogsPanicAsStructuredJSON(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := recoverJSON(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("panic log is not valid JSON: %v", err)
	}
	if entry["msg"] != "panic recovered" || entry["error"] != "boom" || entry["stack"] == nil {
		t.Fatalf("panic log = %#v", entry)
	}
}

func TestHeaderMapStructured(t *testing.T) {
	structured := headerMap(http.Header{
		"User-Agent": []string{"codex/1.0"},
		"Accept":     []string{"a", "b"},
	})
	if structured["User-Agent"] != "codex/1.0" {
		t.Fatalf("single-valued header = %#v", structured["User-Agent"])
	}
	values, ok := structured["Accept"].([]string)
	if !ok || len(values) != 2 || values[0] != "a" || values[1] != "b" {
		t.Fatalf("multi-valued header = %#v", structured["Accept"])
	}
}

func TestBasicAuthProtectsManagementPaths(t *testing.T) {
	hits := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := basicAuth(logger, "admin", "secret", next)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config", nil))
	if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthenticated management request = %d, challenge=%q", recorder.Code, recorder.Header().Get("WWW-Authenticate"))
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config/yaml", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated config yaml request = %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config/secrets", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated secrets request = %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stats request = %d", recorder.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	request.SetBasicAuth("admin", "wrong")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/config", nil)
	request.SetBasicAuth("admin", "secret")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || hits != 1 {
		t.Fatalf("authenticated management request = %d hits=%d", recorder.Code, hits)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if recorder.Code != http.StatusOK || hits != 2 {
		t.Fatalf("proxied path must stay open: status=%d hits=%d", recorder.Code, hits)
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, preflight)
	if recorder.Code != http.StatusOK || hits != 3 {
		t.Fatalf("CORS preflight must stay open: status=%d hits=%d", recorder.Code, hits)
	}
}

func TestGatewayHandlerWorksWithoutListener(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	proxy := &Proxy{
		Client: http.DefaultClient,
		Logger: logger,
	}
	handler := gatewayHandler(logger, proxy, "", "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("open gateway page status = %d", recorder.Code)
	}

	secured := gatewayHandler(logger, proxy, "admin", "secret")
	recorder = httptest.NewRecorder()
	secured.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated management request = %d", recorder.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/config", nil)
	request.SetBasicAuth("admin", "secret")
	recorder = httptest.NewRecorder()
	secured.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated management request = %d", recorder.Code)
	}
}

func secretValuesContain(values map[string]string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestConfigYAMLViewAndImport(t *testing.T) {
	proxy := &Proxy{
		Upstreams:    []Upstream{{Name: "openai", URL: "https://api.openai.com/v1", Authorization: &Authorization{Type: "bearer", Value: "sk-secret"}, AppSelectors: []string{"chat"}}},
		AppSelectors: []AppSelector{{Name: "chat", Match: AppSelectorMatch{Path: []PathMatch{{Operator: "exact", Value: "/v1/chat/completions"}}}}},
		Debug:        true,
		AllowDebug:   true,
		Config:       FileConfig(t.TempDir() + "/config.yaml"),
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config/yaml", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("config yaml status = %d", recorder.Code)
	}
	var viewed Settings
	if err := yaml.Unmarshal(recorder.Body.Bytes(), &viewed); err != nil {
		t.Fatalf("config yaml is not valid YAML: %v\n%s", err, recorder.Body.String())
	}
	if !viewed.Debug || len(viewed.Upstreams) != 1 || viewed.Upstreams[0].Name != "openai" || viewed.Upstreams[0].Authorization.Value != "sk-secret" {
		t.Fatalf("config yaml does not round-trip settings: %s", recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/config/yaml", strings.NewReader(`debug: false
upstreams:
  - url: https://deepseek.example/v1
    name: deepseek
    authorization:
      type: bearer
      value: sk-ds
`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("config yaml import status = %d", recorder.Code)
	}
	var importResult struct {
		Externalized map[string]string `json:"externalized"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &importResult); err != nil {
		t.Fatalf("config yaml import response is not JSON: %v", err)
	}
	if !secretValuesContain(importResult.Externalized, "sk-ds") {
		t.Fatalf("imported literal was not echoed back as externalized: %#v", importResult.Externalized)
	}
	if proxy.Debug || len(proxy.Upstreams) != 1 || proxy.Upstreams[0].Name != "deepseek" || !strings.HasPrefix(proxy.Upstreams[0].Authorization.Value, "secret:") || !secretValuesContain(proxy.SecretValues, "sk-ds") {
		t.Fatalf("imported config not applied: debug=%t upstreams=%#v", proxy.Debug, proxy.Upstreams)
	}
}

func TestConfigYAMLNeverLeaksSecrets(t *testing.T) {
	proxy := &Proxy{
		Upstreams:    []Upstream{{Name: "openai", URL: "https://api.openai.com/v1", Authorization: &Authorization{Type: "bearer", Value: "secret:key1"}}},
		SecretValues: map[string]string{"key1": "sk-super-secret"},
		Config:       FileConfig(t.TempDir() + "/config.yaml"),
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	// The config export is always the disk form (refs only), even if a merge
	// query is attempted; merging happens client-side from the browser storage.
	for _, path := range []string{"/config/yaml", "/config/yaml?merged=1"} {
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		body := recorder.Body.String()
		if strings.Contains(body, "sk-super-secret") || !strings.Contains(body, "secret:key1") {
			t.Fatalf("export %s = %s", path, body)
		}
	}
}

func TestResolveAuthValue(t *testing.T) {
	t.Setenv("AGW_TEST_KEY", "env-value")
	secrets := map[string]string{"openai": "sk-abc"}
	got, err := resolveAuthValue("secret:openai", secrets)
	if err != nil || got != "sk-abc" {
		t.Fatalf("secret ref = %q err=%v", got, err)
	}
	got, err = resolveAuthValue("env:AGW_TEST_KEY", nil)
	if err != nil || got != "env-value" {
		t.Fatalf("env ref = %q err=%v", got, err)
	}
	got, err = resolveAuthValue("plain", nil)
	if err != nil || got != "plain" {
		t.Fatalf("literal = %q err=%v", got, err)
	}
	if _, err := resolveAuthValue("secret:missing", secrets); err == nil {
		t.Fatal("unknown secret must error")
	}
	if _, err := resolveAuthValue("env:AGW_TEST_MISSING_VAR", nil); err == nil {
		t.Fatal("empty env var must error")
	}
}

func TestProxyResolvesSecretAuth(t *testing.T) {
	t.Setenv("AGW_TEST_TOKEN", "sk-resolved")
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := &Proxy{
		Upstreams:    []Upstream{{URL: upstream.URL, Authorization: &Authorization{Type: "bearer", Value: "secret:test"}}},
		SecretValues: map[string]string{"test": "sk-resolved"},
		Client:       http.DefaultClient,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusOK || gotAuth != "Bearer sk-resolved" {
		t.Fatalf("upstream auth = %q status=%d", gotAuth, recorder.Code)
	}
}

func TestConfigYAMLDoesNotLeakSecretValues(t *testing.T) {
	proxy := &Proxy{
		Upstreams:    []Upstream{{Name: "openai", URL: "https://api.openai.com/v1", Authorization: &Authorization{Type: "bearer", Value: "secret:openai"}}},
		SecretValues: map[string]string{"openai": "sk-super-secret"},
		Config:       FileConfig(t.TempDir() + "/config.yaml"),
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config/yaml", nil))
	body := recorder.Body.String()
	if strings.Contains(body, "sk-super-secret") {
		t.Fatalf("config yaml leaks resolved secret value: %s", body)
	}
	if !strings.Contains(body, "secret:openai") {
		t.Fatalf("config yaml does not keep secret references: %s", body)
	}
}

func TestConfigUpdatePreservesSecretReferences(t *testing.T) {
	configPath := t.TempDir() + "/config.yaml"
	proxy := &Proxy{
		Upstreams:    []Upstream{{Name: "openai", URL: "https://api.openai.com/v1", Authorization: &Authorization{Type: "bearer", Value: "secret:openai"}}},
		SecretValues: map[string]string{"openai": "sk-original"},
		Config:       FileConfig(configPath),
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		AllowDebug:   true,
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"debug":true,"upstreams":[{"name":"openai","url":"https://api.openai.com/v1","authorization":{"type":"bearer","value":"secret:openai"}}],"appSelectors":[]}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("config update status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Externalized map[string]string `json:"externalized"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("config update response is not JSON: %v", err)
	}
	if len(result.Externalized) != 0 {
		t.Fatalf("no new secrets expected, got %#v", result.Externalized)
	}
	if !proxy.Debug || proxy.SecretValues["openai"] != "sk-original" || proxy.Upstreams[0].Authorization.Value != "secret:openai" {
		t.Fatalf("secret reference was not preserved: debug=%t values=%#v upstream=%q", proxy.Debug, proxy.SecretValues, proxy.Upstreams[0].Authorization.Value)
	}
	onDisk, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), "sk-original") || !strings.Contains(string(onDisk), "secret:openai") {
		t.Fatalf("config on disk leaked value or dropped reference: %s", onDisk)
	}
}

func TestConfigSecretsEndpoints(t *testing.T) {
	proxy := &Proxy{
		SecretValues: map[string]string{"key1": "sk-one"},
		Config:       FileConfig(t.TempDir() + "/config.yaml"),
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/config/secrets", strings.NewReader(`{"key2":"b64:`+base64.StdEncoding.EncodeToString([]byte("sk-two"))+`","key3":"sk-plain"}`)))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("post secrets status = %d", recorder.Code)
	}
	if proxy.SecretValues["key2"] != "sk-two" || proxy.SecretValues["key3"] != "sk-plain" || proxy.SecretValues["key1"] != "sk-one" {
		t.Fatalf("secrets not merged: %#v", proxy.SecretValues)
	}
	// The endpoint is write-only: reads must be rejected.
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config/secrets", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("get secrets status = %d, want 405 (write-only)", recorder.Code)
	}
	if _, err := decodeSecretValue("b64:!!!"); err == nil {
		t.Fatal("invalid b64 value must error")
	}
	if got, err := decodeSecretValue("qlNkRVG1pHQZDb2qD1uWBxc84ZgvLoXGPWiaclppKNom08Fx"); err != nil || got != "qlNkRVG1pHQZDb2qD1uWBxc84ZgvLoXGPWiaclppKNom08Fx" {
		t.Fatalf("base64-shaped plaintext must pass through: %q err=%v", got, err)
	}
}

func TestConfigViewsKeepsSecretReferencesForBrowserResolution(t *testing.T) {
	views := configViews([]Upstream{
		{Name: "open", Authorization: &Authorization{Type: "bearer", Value: "secret:known"}},
		{Name: "locked", Authorization: &Authorization{Type: "bearer", Value: "secret:missing"}},
		{Name: "plain", Authorization: &Authorization{Type: "bearer", Value: "sk-literal"}},
		{Name: "none", Authorization: &Authorization{Type: "none", Value: ""}},
	})
	if !views[0].AuthIsSecret || views[0].AuthValue != "secret:known" {
		t.Fatalf("secret reference upstream = %#v", views[0])
	}
	if !views[1].AuthIsSecret || views[1].AuthValue != "secret:missing" {
		t.Fatalf("missing secret upstream = %#v", views[1])
	}
	if views[2].AuthIsSecret || views[2].AuthValue != "sk-literal" {
		t.Fatalf("literal upstream = %#v", views[2])
	}
	if views[3].AuthIsSecret || views[3].AuthValue != "" {
		t.Fatalf("none upstream must not be treated as a secret: %#v", views[3])
	}
}

func TestExternalizeSecrets(t *testing.T) {
	upstreams := []Upstream{
		{Authorization: &Authorization{Type: "bearer", Value: "sk-one"}},
		{Authorization: &Authorization{Type: "bearer", Value: "sk-one"}},
		{Authorization: &Authorization{Type: "bearer", Value: "env:TOKEN"}},
		{Authorization: &Authorization{Type: "bearer", Value: "secret:existing"}},
	}
	out, values, changed, err := externalizeSecrets(upstreams, map[string]string{"existing": "sk-old"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("literal auth values should mark a migration")
	}
	if !strings.HasPrefix(out[0].Authorization.Value, "secret:") || out[1].Authorization.Value != out[0].Authorization.Value {
		t.Fatalf("same literal should reuse one key: %q %q", out[0].Authorization.Value, out[1].Authorization.Value)
	}
	if out[2].Authorization.Value != "env:TOKEN" {
		t.Fatalf("env reference must pass through: %q", out[2].Authorization.Value)
	}
	if out[3].Authorization.Value != "secret:existing" || values["existing"] != "sk-old" {
		t.Fatalf("existing secret not preserved: %q values=%#v", out[3].Authorization.Value, values)
	}
	if len(values) != 2 {
		t.Fatalf("values = %#v, want 2 entries", values)
	}
	// References to not-yet-injected secrets are tolerated and kept as-is;
	// the upstream stays locked until the browser provides the value.
	out, values, _, err = externalizeSecrets([]Upstream{{Authorization: &Authorization{Type: "bearer", Value: "secret:missing"}}}, map[string]string{})
	if err != nil || out[0].Authorization.Value != "secret:missing" || len(values) != 0 {
		t.Fatalf("unknown ref must be tolerated: %#v values=%#v err=%v", out, values, err)
	}
}

func TestExternalizeSecretsKeysIndependentPerValue(t *testing.T) {
	// First save: two upstreams sharing one literal share one key.
	first, values, _, err := externalizeSecrets([]Upstream{
		{Authorization: &Authorization{Type: "bearer", Value: "sk-shared"}},
		{Authorization: &Authorization{Type: "bearer", Value: "sk-shared"}},
	}, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Authorization.Value != first[1].Authorization.Value {
		t.Fatalf("identical values should share one key: %q %q", first[0].Authorization.Value, first[1].Authorization.Value)
	}

	// Second save: changing one value must give it a new key while the
	// untouched upstream keeps its original reference.
	second, values2, _, err := externalizeSecrets([]Upstream{
		{Authorization: &Authorization{Type: "bearer", Value: "sk-new"}},
		{Authorization: &Authorization{Type: "bearer", Value: "sk-shared"}},
	}, values)
	if err != nil {
		t.Fatal(err)
	}
	if second[0].Authorization.Value == first[0].Authorization.Value {
		t.Fatal("changed value must get a new key")
	}
	if second[1].Authorization.Value != first[1].Authorization.Value {
		t.Fatalf("unchanged value must keep its key: %q vs %q", second[1].Authorization.Value, first[1].Authorization.Value)
	}
	if values2[strings.TrimPrefix(second[0].Authorization.Value, "secret:")] != "sk-new" {
		t.Fatalf("new key does not map to the new value: %#v", values2)
	}
}

func TestConfigPageDefaultsToDarkSessionJournal(t *testing.T) {
	recorder := httptest.NewRecorder()
	serveConfigPage(recorder, httptest.NewRequest(http.MethodGet, "/", nil), nil, false, false)
	if recorder.Code != http.StatusOK {
		t.Fatalf("config page status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("config page Cache-Control = %q, want no-store", got)
	}
	content := recorder.Body.String()
	for _, expected := range []string{"agw-theme", "'dark'", "theme-toggle", "telemetry-tabbar", "SSE connected", "sessions-panel", "logs-panel", "aria-selected=\"true\"", "Compatible AppSelectors", "selector-table-head", ">Rules<", "updateSelectorSummary", "match-value-field", "match-value-actions", "selector-no-rules", "No rules - matches all requests", ">Actions<", "data-selector", "data-drop-zone", "drop-indicator", "松手后放到这里", "data-duplicate-row", "data-duplicate-selector", "session-table-head", ">Selector<", ">Upstream<", ">Model<", ">Send<", ">Receive<", ">Duration<", "data-payload-modal", "data-log-pretty", "data-log-connection", "yaml-config", "data-config-modal", "data-config-yaml", "data-config-yaml-merged", "secrets-config", "data-secrets-modal", "data-secrets-yaml", "data-session-count", "data-selector-tab-count", "data-upstream-tab-count", "data-log-count", `class="tab-count"`, `class="add-row"`, `id="add-selector"`, `id="routing-tab"`, `id="selectors-tab"`, `data-telemetry-tab="routing"`, `data-telemetry-tab="selectors"`, `id="routing-panel" role="tabpanel" aria-labelledby="routing-tab" hidden`, `id="selectors-panel" role="tabpanel" aria-labelledby="selectors-tab"`, `id="sessions-panel" role="tabpanel" aria-labelledby="sessions-tab" hidden`, "viewFromHash", "hashchange", "location.hash", "scheduleSessionReconcile", "sessionGestureActive", "lastSessionHTML", "data-tab-menu-button", `class="tab-menu-button"`, "closeTabMenu", "hamburger-mode", "updateTabLayoutMode", `rel="manifest"`, "og:title", `name="theme-color"`, `rel="icon" href="/favicon.ico"`, "apple-touch-icon", "icon-512.png", `>AppSelector<`, `>Routing<`, `>Sessions<`, `>Logs<`, `data-rule-type-option="method"`, `id="stats-tab"`, `data-telemetry-tab="stats"`, `id="stats-panel"`, `id="stats-view"`, "EventSource('/stats/stream?window=' + statsWindow)"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config page missing %q", expected)
		}
	}
	if strings.Count(content, `class="live-dot"`) != 5 {
		t.Fatalf("all five workspace tabs should carry a live indicator")
	}
	if strings.Index(content, `id="selectors-tab"`) > strings.Index(content, `id="routing-tab"`) {
		t.Fatalf("AppSelector should be the first tab")
	}
	for _, expected := range []string{"data-rule", "data-rule-type", "rule-kind", "data-add-rule", "data-rule-type-option", `data-rule-type-option="query"`, "data-rule-enabled", "data-rule-delete", "data-rule-empty", "rule-switch"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config page missing rule UI %q", expected)
		}
	}
	for _, expected := range []string{"reconcileSessionCards", "updateSessionCard", "openPayloadModal", "EventSource('/sessions/stream')"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config page missing session journal JS %q", expected)
		}
	}
	if strings.Contains(content, "data-config-yaml-merged checked") {
		t.Fatalf("config page must not enable merged YAML display by default")
	}
	routingPanel := strings.Index(content, `id="routing-panel" role="tabpanel" aria-labelledby="routing-tab" hidden`)
	selectorsPanel := strings.Index(content, `id="selectors-panel" role="tabpanel" aria-labelledby="selectors-tab"`)
	addUpstream := strings.Index(content, `id="add-upstream"`)
	if routingPanel < 0 || selectorsPanel < 0 || addUpstream <= routingPanel || addUpstream >= selectorsPanel {
		t.Fatalf("upstream add button should live inside the routing panel")
	}
	tabbarStart := strings.Index(content, `class="telemetry-tabbar"`)
	tabbarEnd := strings.Index(content[tabbarStart:], "</div>")
	if tabbarStart < 0 || tabbarEnd < 0 || addUpstream <= tabbarStart+tabbarEnd {
		t.Fatalf("add-upstream should live inside a panel below the tab bar: start=%d end=%d add=%d", tabbarStart, tabbarEnd, addUpstream)
	}
}

func TestConfigPageRendersBodyMatchRules(t *testing.T) {
	recorder := httptest.NewRecorder()
	serveConfigPage(recorder, httptest.NewRequest(http.MethodGet, "/", nil), []AppSelector{
		{Name: "deepseek", Match: AppSelectorMatch{Body: []BodyMatch{{Field: "model", Operator: "prefix", Value: "deepseek", CaseSensitive: true}}}, Rewrite: []FieldRewrite{{Field: "model", Value: "gpt-5.6-luna"}}},
	}, false, true)
	content := recorder.Body.String()
	for _, expected := range []string{`value="deepseek"`, `value="model"`, `data-rule-type="body"`, `data-case-sensitive="true"`} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config page body rules missing %q", expected)
		}
	}
	for _, expected := range []string{`value="gpt-5.6-luna"`, `data-rule-type="rewrite"`} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config page rewrite rules missing %q", expected)
		}
	}
}

func TestConfigPageDebugToggleState(t *testing.T) {
	recorder := httptest.NewRecorder()
	serveConfigPage(recorder, httptest.NewRequest(http.MethodGet, "/", nil), nil, true, true)
	content := recorder.Body.String()
	if !strings.Contains(content, `id="debug-toggle" type="checkbox" checked`) {
		t.Fatalf("debug toggle should be checked when allowed and debug is on")
	}

	recorder = httptest.NewRecorder()
	serveConfigPage(recorder, httptest.NewRequest(http.MethodGet, "/", nil), nil, true, false)
	content = recorder.Body.String()
	if strings.Contains(content, `class="debug-toggle"`) {
		t.Fatalf("debug toggle must be hidden entirely without --allow-debug")
	}
}

func TestConfigPageRendersMethodRule(t *testing.T) {
	recorder := httptest.NewRecorder()
	serveConfigPage(recorder, httptest.NewRequest(http.MethodGet, "/", nil), []AppSelector{{Name: "write", Methods: []string{"POST", "PUT"}}}, false, true)
	content := recorder.Body.String()
	for _, expected := range []string{`data-rule-type="method"`, `data-method="POST" checked`, `data-method="PUT" checked`, `data-method="DELETE"`} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config page missing method rule %q", expected)
		}
	}
	if strings.Contains(content, `data-method="GET" checked`) || strings.Contains(content, `data-method="DELETE" checked`) {
		t.Fatalf("unconfigured methods must not be checked")
	}
}

func TestPWAAssetsServed(t *testing.T) {
	proxy := &Proxy{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	tests := []struct {
		path        string
		contentType string
	}{
		{"/manifest.json", "application/manifest+json"},
		{"/favicon.ico", "image/x-icon"},
		{"/favicon.svg", "image/svg+xml"},
		{"/icon-192.png", "image/png"},
		{"/icon-512.png", "image/png"},
	}
	for _, tt := range tests {
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d", tt.path, recorder.Code)
		}
		if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, tt.contentType) {
			t.Fatalf("%s content type = %q, want prefix %q", tt.path, got, tt.contentType)
		}
		if recorder.Body.Len() == 0 {
			t.Fatalf("%s served empty body", tt.path)
		}
		if got := recorder.Header().Get("Cache-Control"); got == "" {
			t.Fatalf("%s missing Cache-Control", tt.path)
		}
	}
}

func TestConfigFragmentRendersMultiSelectForAppSelectors(t *testing.T) {
	recorder := httptest.NewRecorder()
	serveConfigFragment(recorder, []Upstream{
		{Name: "primary", URL: "https://example.com/v1", AppSelectors: []string{"codex", "fallback"}},
	})
	content := recorder.Body.String()
	for _, expected := range []string{"data-multi-select", "data-ms-trigger", "data-ms-menu", `value="codex, fallback"`} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config fragment missing %q", expected)
		}
	}
	if strings.Contains(content, `placeholder="codex, default"`) {
		t.Fatalf("config fragment still uses a free-text app selector input")
	}
}

func TestConfigFragmentRendersSecretLockWithoutResolving(t *testing.T) {
	recorder := httptest.NewRecorder()
	serveConfigFragment(recorder, []Upstream{
		{Name: "locked", URL: "https://example.com/v1", Authorization: &Authorization{Type: "bearer", Value: "secret:missing"}},
		{Name: "none", URL: "https://example.com/v2", Authorization: &Authorization{Type: "none", Value: ""}},
	})
	content := recorder.Body.String()
	for _, expected := range []string{`data-lucide="lock"`, `<span class="auth-value"><input class="field-input auth-placeholder" type="password" value="••••••" aria-label="认证值（锁定）" disabled></span>`, `<span class="auth-locked" data-secret-key="secret:missing" title="当前浏览器未持有该密钥，已锁定"><i data-lucide="lock"></i></span>`, `<input type="hidden" data-auth-value value="secret:missing">`} {
		if !strings.Contains(content, expected) {
			t.Fatalf("config fragment missing secret lock %q", expected)
		}
	}
	// The reference must only appear in attributes (data-secret-key and the
	// hidden value), never as visible text in the row.
	if strings.Count(content, "secret:missing") != 2 {
		t.Fatalf("secret reference should appear exactly twice (attribute only), got:\n%s", content)
	}
	if strings.Count(content, `data-secret-key=`) != 1 {
		t.Fatalf("only the secret-reference upstream should carry a secret key, got:\n%s", content)
	}
	if !strings.Contains(content, `<input type="hidden" data-auth-value value="">`) {
		t.Fatalf("none-type upstream should render an empty hidden auth value, got:\n%s", content)
	}
}

func TestStatsAggregation(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	base := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	hub.mu.Lock()
	hub.history = []*statsEntry{
		{sessionID: "s1", started: base, completed: base.Add(2 * time.Second), status: 200, state: "completed", reqBytes: 50, respBytes: 100, model: "gpt-5", upstream: "openai", selector: "codex", method: "POST", path: "/responses"},
		{sessionID: "s1", started: base.Add(time.Minute), completed: base.Add(time.Minute + 4*time.Second), status: 502, state: "completed", reqBytes: 50, respBytes: 40, model: "gpt-5", upstream: "openai", selector: "codex", method: "POST", path: "/responses", isError: true},
		{sessionID: "s2", started: base.Add(2 * time.Minute), completed: base.Add(2*time.Minute + 500*time.Millisecond), status: 200, state: "completed", respBytes: 30, upstream: "openai", method: "GET", path: "/healthz"},
	}
	hub.mu.Unlock()

	view := hub.stats("all")
	if view.Requests != 3 || view.Sessions != 2 || view.Errors != 1 {
		t.Fatalf("totals = %d requests / %d sessions / %d errors", view.Requests, view.Sessions, view.Errors)
	}
	if view.ErrorRate != "33%" {
		t.Fatalf("error rate = %q, want 33%%", view.ErrorRate)
	}
	if view.AvgDuration != "2.167s" || view.P95Duration != "4s" || view.MaxDuration != "4s" {
		t.Fatalf("latency avg/p95/max = %q/%q/%q", view.AvgDuration, view.P95Duration, view.MaxDuration)
	}
	if view.InBytes != "100 B" || view.OutBytes != "170 B" {
		t.Fatalf("traffic in/out = %q/%q", view.InBytes, view.OutBytes)
	}
	if len(view.Buckets) != 3 {
		t.Fatalf("minute buckets = %d, want 3", len(view.Buckets))
	}
	if view.Buckets[0].Count != 1 || view.Buckets[0].Errors != 0 || view.Buckets[1].Count != 1 || view.Buckets[1].Errors != 1 {
		t.Fatalf("bucket counts = %#v", view.Buckets)
	}
	if len(view.Statuses) != 2 || view.Statuses[0].Name != "2xx 成功" || view.Statuses[0].Count != 2 {
		t.Fatalf("status breakdown = %#v", view.Statuses)
	}
	if len(view.Upstreams) != 1 || view.Upstreams[0].Name != "openai" || view.Upstreams[0].Count != 3 {
		t.Fatalf("upstream breakdown = %#v", view.Upstreams)
	}
	if len(view.Selectors) != 2 || view.Selectors[0].Name != "codex" || view.Selectors[1].Name != "未匹配" {
		t.Fatalf("selector breakdown = %#v", view.Selectors)
	}
	if len(view.Models) != 2 || view.Models[0].Name != "gpt-5" || view.Models[0].Count != 2 || view.Models[1].Name != "未知模型" {
		t.Fatalf("model breakdown = %#v", view.Models)
	}
	if len(view.TopPaths) != 2 || view.TopPaths[0].Path != "/responses" || view.TopPaths[0].Count != 2 {
		t.Fatalf("top paths = %#v", view.TopPaths)
	}
}

func TestStatsWindowFilter(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	now := time.Now()
	hub.mu.Lock()
	hub.history = []*statsEntry{
		{sessionID: "old", started: now.Add(-2 * time.Hour), completed: now.Add(-2*time.Hour + time.Second), status: 200, state: "completed"},
		{sessionID: "recent", started: now.Add(-10 * time.Minute), completed: now, status: 200, state: "completed"},
	}
	hub.mu.Unlock()

	all := hub.stats("all")
	if all.Requests != 2 || all.Sessions != 2 || all.Empty {
		t.Fatalf("all-window totals = %#v", all)
	}
	hour := hub.stats("1h")
	if hour.Requests != 1 || hour.Sessions != 1 || hour.Empty {
		t.Fatalf("1h-window totals = %#v", hour)
	}
	day := hub.stats("24h")
	if day.Requests != 2 || day.Empty {
		t.Fatalf("24h-window totals = %#v", day)
	}
	if got := hub.stats("bogus").Window; got != "all" {
		t.Fatalf("unknown window should normalize to all, got %q", got)
	}
	for _, view := range []statsView{all, hour, day} {
		if len(view.Windows) != 5 {
			t.Fatalf("window options for %q = %d, want 5", view.Window, len(view.Windows))
		}
	}
	if !all.Windows[4].Active || !hour.Windows[0].Active || !day.Windows[1].Active {
		t.Fatalf("active window flags wrong: %#v / %#v / %#v", all.Windows, hour.Windows, day.Windows)
	}
}

func TestStatsTracksRequestsThroughProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("accepted"))
	}))
	defer upstream.Close()

	hub := newSessionHub()
	defer hub.close()
	proxy := &Proxy{
		Upstreams: []Upstream{{URL: upstream.URL, Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Sessions:  hub,
	}
	handler := requestLogger(proxy.Logger, proxy)
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("payload"))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	view := hub.stats("all")
	if view.Requests != 1 || view.Sessions != 1 || view.Errors != 0 {
		t.Fatalf("stats after proxied request = %#v", view)
	}
	if len(view.Statuses) != 1 || view.Statuses[0].Name != "2xx 成功" || view.Statuses[0].Count != 1 {
		t.Fatalf("proxied 202 should count as 2xx: %#v", view.Statuses)
	}
	if len(hub.history) != 1 {
		t.Fatalf("stats history should hold one entry, got %d", len(hub.history))
	}
}

func TestStatsRouteRendersFragment(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	proxy := &Proxy{Logger: logger, Sessions: hub}

	empty := httptest.NewRecorder()
	proxy.ServeHTTP(empty, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), "暂无统计数据") {
		t.Fatalf("empty stats fragment = %d %q", empty.Code, empty.Body.String())
	}
	if !strings.Contains(empty.Body.String(), "data-stats-window-button") {
		t.Fatalf("empty stats fragment should still render the window filter: %q", empty.Body.String())
	}

	now := time.Now()
	hub.mu.Lock()
	hub.history = []*statsEntry{
		{sessionID: "s1", started: now, completed: now.Add(time.Second), status: 200, state: "completed", reqBytes: 10, respBytes: 20, model: "gpt-5", upstream: "openai", selector: "codex", method: "POST", path: "/responses"},
	}
	hub.mu.Unlock()

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/stats", nil))
	content := recorder.Body.String()
	for _, expected := range []string{"请求总数", "错误率", "请求时间分布", "HTTP 状态", "热门路径", "openai", "gpt-5", "codex", "stats-chart-bar", "/responses", `data-stats-window="all"`, `data-stats-window-button="1h"`, `data-stats-window-button="all"`} {
		if !strings.Contains(content, expected) {
			t.Fatalf("stats fragment missing %q:\n%s", expected, content)
		}
	}

	windowed := httptest.NewRecorder()
	proxy.ServeHTTP(windowed, httptest.NewRequest(http.MethodGet, "/stats?window=24h", nil))
	windowContent := windowed.Body.String()
	if !strings.Contains(windowContent, `data-stats-window="24h"`) || !strings.Contains(windowContent, `<button class="stats-window is-active" type="button" data-stats-window-button="24h"`) {
		t.Fatalf("windowed stats fragment should mark 24h active:\n%s", windowContent)
	}
}

func TestStatsBreakdownFoldsOthers(t *testing.T) {
	hub := newSessionHub()
	defer hub.close()
	now := time.Now()
	hub.mu.Lock()
	for i := 0; i < 10; i++ {
		hub.history = append(hub.history, &statsEntry{
			sessionID: fmt.Sprintf("s%d", i), started: now, completed: now.Add(time.Second), status: 200, state: "completed",
			model: fmt.Sprintf("model-%d", i), upstream: fmt.Sprintf("up-%d", i), selector: fmt.Sprintf("sel-%d", i),
		})
	}
	hub.mu.Unlock()

	view := hub.stats("all")
	for name, dimension := range map[string][]statsBar{"model": view.Models, "upstream": view.Upstreams, "selector": view.Selectors} {
		if len(dimension) != statsTopN+1 {
			t.Fatalf("%s breakdown should keep %d rows plus 其他, got %d: %#v", name, statsTopN, len(dimension), dimension)
		}
		tail := dimension[len(dimension)-1]
		if tail.Name != "其他" || tail.Count != 2 {
			t.Fatalf("%s breakdown should fold the two rarest entries into 其他 with count 2, got %#v", name, tail)
		}
	}
}

func TestStatsPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	hub := newSessionHubPersistent(dir)
	tracked := hub.start(httptest.NewRequest(http.MethodPost, "/v1/responses", nil))
	tracked.connected(200)
	tracked.setUpstream("openai")
	tracked.setAppSelector("codex")
	tracked.setRequestBody("application/json", []byte(`{"model":"gpt-5"}`))
	tracked.complete(200, 1234, nil)
	hub.close()

	lines, err := os.ReadFile(filepath.Join(dir, "stats.jsonl"))
	if err != nil || len(lines) == 0 {
		t.Fatalf("stats log not written: %v", err)
	}
	if strings.Count(string(lines), "\n") != 1 {
		t.Fatalf("stats log should hold exactly one completed request, got:\n%s", lines)
	}

	restarted := newSessionHubPersistent(dir)
	defer restarted.close()
	view := restarted.stats("all")
	if view.Requests != 1 || view.Sessions != 1 || view.Errors != 0 {
		t.Fatalf("restored stats = %#v", view)
	}
	if len(view.Models) != 1 || view.Models[0].Name != "gpt-5" || view.Models[0].Count != 1 {
		t.Fatalf("restored model breakdown = %#v", view.Models)
	}
	if len(view.Upstreams) != 1 || view.Upstreams[0].Name != "openai" {
		t.Fatalf("restored upstream breakdown = %#v", view.Upstreams)
	}
	if len(view.Selectors) != 1 || view.Selectors[0].Name != "codex" {
		t.Fatalf("restored selector breakdown = %#v", view.Selectors)
	}
}

func TestStatsBackfillsFromSessionFiles(t *testing.T) {
	dir := t.TempDir()
	sessionDir := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	record := sessionRecord{ID: "s-legacy", Requests: []*sessionRequest{
		{Sequence: 1, Method: "POST", Path: "/responses", StartedAt: now.Add(-time.Hour), CompletedAt: now.Add(-time.Hour + time.Second), Status: 200, State: "completed", RequestBytes: 10, ResponseBytes: 20, Model: "legacy-model", Upstream: "legacy-up"},
		{Sequence: 2, Method: "POST", Path: "/responses", StartedAt: now.Add(-30 * time.Minute), Status: 0, State: "streaming"},
	}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "s-legacy.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	hub := newSessionHubPersistent(dir)
	view := hub.stats("all")
	if view.Requests != 1 {
		t.Fatalf("backfilled stats should skip the in-flight request, got %d", view.Requests)
	}
	if len(view.Models) != 1 || view.Models[0].Name != "legacy-model" {
		t.Fatalf("backfilled model breakdown = %#v", view.Models)
	}
	hub.close()

	// A restart must read stats.jsonl as the single source of truth and must
	// not double-count the backfilled entries.
	restarted := newSessionHubPersistent(dir)
	defer restarted.close()
	if got := restarted.stats("all").Requests; got != 1 {
		t.Fatalf("restart after backfill should keep one request, got %d", got)
	}
}

func TestWriteSessionSSERemovesCarriageReturns(t *testing.T) {
	var output bytes.Buffer
	if err := writeSessionSSE(&output, "first\r\nsecond"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\r") || !strings.Contains(output.String(), "event: sessions\n") {
		t.Fatalf("invalid session SSE frame: %q", output.String())
	}
}

func TestSessionRouteShowsTrackedProxyRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("accepted"))
	}))
	defer upstream.Close()

	hub := newSessionHub()
	defer hub.close()
	proxy := &Proxy{
		Upstreams: []Upstream{{URL: upstream.URL, Authorization: &Authorization{Type: "none"}}},
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Sessions:  hub,
	}
	handler := requestLogger(proxy.Logger, proxy)
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("payload"))
	request.Header.Set("Session-Id", "session-route")
	request.Header.Set("Authorization", "Bearer client-secret")
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/sessions", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Intercepted request") {
		t.Fatalf("session route response = %d %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "client-secret") || !strings.Contains(recorder.Body.String(), "[redacted]") {
		t.Fatalf("session route exposes authorization: %q", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), ">payload<") {
		t.Fatalf("session route embeds request body: %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Gateway events") || !strings.Contains(recorder.Body.String(), "attempt") || !strings.Contains(recorder.Body.String(), "response") {
		t.Fatalf("session route does not show gateway events: %q", recorder.Body.String())
	}
	cards := hub.cards()
	requestPayload := httptest.NewRecorder()
	proxy.ServeHTTP(requestPayload, httptest.NewRequest(http.MethodGet, "/sessions/"+cards[0].ID+"/request", nil))
	if requestPayload.Code != http.StatusOK || requestPayload.Body.String() != "payload" {
		t.Fatalf("request payload response = %d %q", requestPayload.Code, requestPayload.Body.String())
	}
	responsePayload := httptest.NewRecorder()
	proxy.ServeHTTP(responsePayload, httptest.NewRequest(http.MethodGet, "/sessions/"+cards[0].ID+"/response", nil))
	if responsePayload.Code != http.StatusOK || responsePayload.Body.String() != "accepted" {
		t.Fatalf("response payload response = %d %q", responsePayload.Code, responsePayload.Body.String())
	}
}
