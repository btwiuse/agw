package agw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const statsTopN = 8

var statsWindowOptions = []statsWindow{
	{Key: "1h", Label: "1 小时"},
	{Key: "24h", Label: "24 小时"},
	{Key: "7d", Label: "7 天"},
	{Key: "30d", Label: "30 天"},
	{Key: "all", Label: "全部"},
}

func validStatsWindow(window string) bool {
	if window == "" {
		return false
	}
	for _, option := range statsWindowOptions {
		if option.Key == window {
			return true
		}
	}
	return false
}

// statsCutoff returns the earliest request time included in a window; the
// zero time means "no filter, aggregate everything".
func statsCutoff(window string) time.Time {
	switch window {
	case "1h":
		return time.Now().Add(-time.Hour)
	case "24h":
		return time.Now().Add(-24 * time.Hour)
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour)
	default:
		return time.Time{}
	}
}

func windowOptions(window string) []statsWindow {
	options := make([]statsWindow, 0, len(statsWindowOptions))
	for _, option := range statsWindowOptions {
		active := option.Key == window
		options = append(options, statsWindow{Key: option.Key, Label: option.Label, Active: active})
	}
	return options
}

// statsView is the fully precomputed render model for the stats fragment. All
// numbers, percentages and bar heights are computed server side so the
// template stays free of logic.
type statsView struct {
	Requests     int64
	Sessions     int64
	Errors       int64
	ErrorRate    string
	InBytes      string
	OutBytes     string
	AvgDuration  string
	P95Duration  string
	MaxDuration  string
	SpanLabel    string
	BucketLabel  string
	MaxBucket    int64
	Buckets      []statsBucket
	Statuses     []statsBar
	States       []statsBar
	Upstreams    []statsBar
	Selectors    []statsBar
	Models       []statsBar
	Methods      []statsBar
	TopPaths     []statsPath
	UpstreamRows []statsUpstreamRow
	Daily        []statsDailyRow
	ModelRows    []statsModelRow
	// Token accounting. HasTokens reports that at least one request carried a
	// parsed usage object; HasCost that a pricing table is configured (cost
	// columns render only then). Token strings are preformatted for display.
	HasTokens        bool
	HasCost          bool
	TotalTokens      string
	InputTokens      string
	OutputTokens     string
	CacheReadTokens  string
	CacheWriteTokens string
	InputPct         string
	OutputPct        string
	Cost             string
	SeriesJSON       string
	Window           string
	Windows          []statsWindow
	Empty            bool
}

type statsWindow struct {
	Key    string
	Label  string
	Active bool
}

type statsBucket struct {
	Label  string
	Time   string
	Unix   int64
	Count  int64
	Errors int64
	H      int
	EH     int
	AvgMs  float64
	P50Ms  float64
	P95Ms  float64
	InTok  int64
	OutTok int64
}

type statsBar struct {
	Name  string
	Count int64
	Pct   string
	H     int
	Class string
}

type statsPath struct {
	Path   string
	Method string
	Count  int64
}

// statsEntry is one request flattened for aggregation. Entries live in the
// session hub's in-memory stats history, which retains every request the
// process has seen (plus what was loaded from persisted session files at
// startup), independently of the journal's recent-session eviction.
type statsEntry struct {
	sessionID string
	started   time.Time
	completed time.Time
	status    int
	state     string
	upstream  string
	selector  string
	model     string
	method    string
	path      string
	reqBytes  int64
	respBytes int64
	tokens    tokenUsage
	cost      float64
	isError   bool
}

// tokenUsage is the per-request token accounting extracted from upstream
// responses. The scanner normalizes provider differences into one shape:
// OpenAI-style prompt/completion totals, Anthropic-style input/output plus
// cache reads/creations, and Gemini-style promptTokenCount/candidatesTokenCount
// all land on the same fields. InputTokens always includes cached input tokens
// when the provider reports them that way (OpenAI), while CacheReadTokens /
// CacheWriteTokens stay available as supplementary detail (Anthropic).
type tokenUsage struct {
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	TotalTokens      int64
	// Seen reports whether any usage object was parsed from the response, even
	// a zero one; a provider can answer with a valid but empty usage block.
	Seen bool
}

// total reports the total token count, falling back to input+output when the
// provider never sent an explicit total.
func (u tokenUsage) total() int64 {
	if u.TotalTokens > 0 {
		return u.TotalTokens
	}
	return u.InputTokens + u.OutputTokens
}

const (
	// usageScanBufferCap bounds the scanner's rolling tail buffer. Usage
	// objects live at the end of responses (final SSE chunk / message_delta),
	// so keeping the tail is all that matters; older bytes are dropped.
	usageScanBufferCap = 1 << 18
	// usageScanMaxObject is the largest single usage object the scanner will
	// walk. Real usage objects are a handful of fields; the cap only guards
	// against pathological values making the scan quadratic.
	usageScanMaxObject = 1 << 16
)

// usageScanner incrementally watches raw response bytes for provider usage
// objects (the "usage" key of OpenAI/Anthropic payloads and the
// "usageMetadata" key of Gemini payloads) so token totals survive streaming,
// chunk boundaries and protocol differences. It never buffers more than
// usageScanBufferCap bytes and keeps per-field maxima, which is the correct
// merge rule across all providers: Anthropic splits input (message_start) and
// output (message_delta) into separate usage objects, OpenAI repeats a full
// object only in the final chunk, and Gemini reports one object per response.
type usageScanner struct {
	buf     []byte
	scanPos int
	usage   tokenUsage
}

// tally returns the final accumulated usage. Call it after the response body
// has been fully streamed.
func (s *usageScanner) tally() tokenUsage {
	if s == nil {
		return tokenUsage{}
	}
	return s.usage
}

// feed appends a response chunk and scans it for usage objects. It is safe to
// call once per streamed Write; the tally is final after the stream ends.
func (s *usageScanner) feed(data []byte) {
	if s == nil || len(data) == 0 {
		return
	}
	s.buf = append(s.buf, data...)
	if len(s.buf) > usageScanBufferCap {
		drop := len(s.buf) - usageScanBufferCap
		s.buf = s.buf[drop:]
		if s.scanPos < drop {
			s.scanPos = 0
		} else {
			s.scanPos -= drop
		}
	}
	s.scan()
}

// scan walks the buffer from the last scan position, parsing every complete
// usage object it can reach. An object that is still incomplete (split across
// chunks) leaves the scan position at its key so the next feed retries it.
func (s *usageScanner) scan() {
	for {
		idx := s.findUsageKey(s.scanPos)
		if idx < 0 {
			// Keep the tail unscanned so a key split across chunk boundaries
			// ("usageMetada" + "ta") is found once the next chunk arrives.
			tail := len(s.buf) - 14
			if tail > s.scanPos {
				s.scanPos = tail
			} else {
				s.scanPos = len(s.buf)
			}
			return
		}
		valueStart, ok := s.valueAfterKey(idx)
		if !ok || valueStart >= len(s.buf) {
			// Incomplete object; retry when more bytes arrive.
			s.scanPos = idx
			return
		}
		if s.buf[valueStart] != '{' {
			// "usage": null or a non-object value; skip past the key.
			s.scanPos = valueStart + 1
			continue
		}
		end, complete := s.balancedObject(valueStart)
		if !complete {
			s.scanPos = idx
			return
		}
		var parsed usagePayload
		if json.Unmarshal(s.buf[valueStart:end+1], &parsed) == nil {
			s.usage.merge(parsed)
		}
		s.scanPos = end + 1
	}
}

// findUsageKey locates the next "usage" or "usageMetadata" JSON key starting
// from pos, returning its index or -1. The shorter literal cannot collide with
// the longer one: "usageMetadata" has no closing quote after "usage".
func (s *usageScanner) findUsageKey(pos int) int {
	buf := s.buf
	for i := pos; i+7 <= len(buf); i++ {
		if buf[i] != '"' {
			continue
		}
		// A backslash before the quote means the key is escaped inside a
		// string value (e.g. assistant text quoting a usage object); skip it.
		if i > 0 && buf[i-1] == '\\' {
			continue
		}
		if string(buf[i:i+7]) == `"usage"` {
			return i
		}
		if i+15 <= len(buf) && string(buf[i:i+15]) == `"usageMetadata"` {
			return i
		}
	}
	return -1
}

// valueAfterKey returns the index just past ":" following a usage key, or ok
// false when the value is still pending.
func (s *usageScanner) valueAfterKey(keyStart int) (int, bool) {
	i := keyStart
	for i < len(s.buf) && s.buf[i] != ':' {
		i++
	}
	if i >= len(s.buf) {
		return 0, false
	}
	i++
	for i < len(s.buf) && (s.buf[i] == ' ' || s.buf[i] == '\t' || s.buf[i] == '\n' || s.buf[i] == '\r') {
		i++
	}
	if i >= len(s.buf) {
		return 0, false
	}
	return i, true
}

// balancedObject returns the index of the closing brace of the JSON object
// starting at start, or complete=false when the buffer ends first. Strings and
// escapes inside the object are respected so "}" in a value never confuses the
// walker.
func (s *usageScanner) balancedObject(start int) (int, bool) {
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s.buf); i++ {
		if i-start > usageScanMaxObject {
			return 0, false
		}
		c := s.buf[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// usagePayload is the union of provider usage objects; pointer fields let the
// merger distinguish "absent" from "zero".
type usagePayload struct {
	PromptTokens         *int64 `json:"prompt_tokens"`
	CompletionTokens     *int64 `json:"completion_tokens"`
	TotalTokens          *int64 `json:"total_tokens"`
	InputTokens          *int64 `json:"input_tokens"`
	OutputTokens         *int64 `json:"output_tokens"`
	CacheReadTokens      *int64 `json:"cache_read_input_tokens"`
	CacheCreationTokens  *int64 `json:"cache_creation_input_tokens"`
	PromptCacheHit       *int64 `json:"prompt_cache_hit_tokens"`
	PromptTokenCount     *int64 `json:"promptTokenCount"`
	CandidatesTokenCount *int64 `json:"candidatesTokenCount"`
	TotalTokenCount      *int64 `json:"totalTokenCount"`
	PromptTokensDetails  *struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

// merge folds one parsed usage object into the tally. Every field is merged
// with per-field maxima; Anthropic's split input/output objects and OpenAI's
// repeated final-chunk object are both handled by that rule.
func (u *tokenUsage) merge(parsed usagePayload) {
	u.Seen = true
	if parsed.PromptTokens != nil {
		u.InputTokens = max64(u.InputTokens, *parsed.PromptTokens)
	}
	if parsed.InputTokens != nil {
		u.InputTokens = max64(u.InputTokens, *parsed.InputTokens)
	}
	if parsed.PromptTokenCount != nil {
		u.InputTokens = max64(u.InputTokens, *parsed.PromptTokenCount)
	}
	if parsed.CompletionTokens != nil {
		u.OutputTokens = max64(u.OutputTokens, *parsed.CompletionTokens)
	}
	if parsed.OutputTokens != nil {
		u.OutputTokens = max64(u.OutputTokens, *parsed.OutputTokens)
	}
	if parsed.CandidatesTokenCount != nil {
		u.OutputTokens = max64(u.OutputTokens, *parsed.CandidatesTokenCount)
	}
	if parsed.TotalTokens != nil {
		u.TotalTokens = max64(u.TotalTokens, *parsed.TotalTokens)
	}
	if parsed.TotalTokenCount != nil {
		u.TotalTokens = max64(u.TotalTokens, *parsed.TotalTokenCount)
	}
	if parsed.CacheReadTokens != nil {
		u.CacheReadTokens = max64(u.CacheReadTokens, *parsed.CacheReadTokens)
	}
	if parsed.CacheCreationTokens != nil {
		u.CacheWriteTokens = max64(u.CacheWriteTokens, *parsed.CacheCreationTokens)
	}
	if parsed.PromptCacheHit != nil {
		u.CacheReadTokens = max64(u.CacheReadTokens, *parsed.PromptCacheHit)
	}
	if parsed.PromptTokensDetails != nil && parsed.PromptTokensDetails.CachedTokens != nil {
		u.CacheReadTokens = max64(u.CacheReadTokens, *parsed.PromptTokensDetails.CachedTokens)
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// pricingCost estimates the USD cost of one request from the pricing table:
// the longest matching model-prefix rule wins, and requests whose model has no
// rule (or that carried no usage object) cost nothing.
func pricingCost(pricing []PricingRule, model string, usage tokenUsage) float64 {
	if !usage.Seen || len(pricing) == 0 || model == "" {
		return 0
	}
	best := -1
	bestLen := 0
	for i, rule := range pricing {
		if rule.ModelPrefix == "" || len(rule.ModelPrefix) <= bestLen {
			continue
		}
		if strings.HasPrefix(model, rule.ModelPrefix) {
			best = i
			bestLen = len(rule.ModelPrefix)
		}
	}
	if best < 0 {
		return 0
	}
	rule := pricing[best]
	return float64(usage.InputTokens)/1_000_000*rule.InputPer1M + float64(usage.OutputTokens)/1_000_000*rule.OutputPer1M
}

// formatCost renders a dollar amount like the reference dashboard's compact
// money formatting: cents for small sums, then k/M abbreviations.
func formatCost(cost float64) string {
	if cost == 0 {
		return "$0.00"
	}
	if cost >= 1_000_000 {
		return fmt.Sprintf("$%.1fM", cost/1_000_000)
	}
	if cost >= 1000 {
		return fmt.Sprintf("$%.1fk", cost/1000)
	}
	if cost >= 100 {
		return fmt.Sprintf("$%.0f", cost)
	}
	if cost >= 1 {
		return fmt.Sprintf("$%.2f", cost)
	}
	return fmt.Sprintf("$%.4f", cost)
}

func errorState(state string) bool {
	switch state {
	case "client closed", "timed out", "interrupted":
		return true
	default:
		return false
	}
}

// isFinalState reports whether a request reached a terminal state; only those
// are persisted to the stats log.
func isFinalState(state string) bool {
	switch state {
	case "completed", "client closed", "timed out", "interrupted":
		return true
	default:
		return false
	}
}

// statsRecord is the on-disk form of one stats entry, appended as a JSON line
// to data/stats.jsonl when a request completes. Field names follow the
// session journal files so both logs stay readable side by side.
type statsRecord struct {
	SessionID       string    `json:"SessionID"`
	StartedAt       time.Time `json:"StartedAt"`
	CompletedAt     time.Time `json:"CompletedAt"`
	Status          int       `json:"Status"`
	State           string    `json:"State"`
	Upstream        string    `json:"Upstream,omitempty"`
	AppSelector     string    `json:"AppSelector,omitempty"`
	Model           string    `json:"Model,omitempty"`
	Method          string    `json:"Method,omitempty"`
	Path            string    `json:"Path,omitempty"`
	RequestBytes    int64     `json:"RequestBytes,omitempty"`
	ResponseBytes   int64     `json:"ResponseBytes,omitempty"`
	TokenInput      int64     `json:"TokenInput,omitempty"`
	TokenOutput     int64     `json:"TokenOutput,omitempty"`
	TokenCacheRead  int64     `json:"TokenCacheRead,omitempty"`
	TokenCacheWrite int64     `json:"TokenCacheWrite,omitempty"`
	TokenTotal      int64     `json:"TokenTotal,omitempty"`
}

func statsRecordFromRequest(sessionID string, request *sessionRequest) statsRecord {
	return statsRecord{
		SessionID: sessionID, StartedAt: request.StartedAt, CompletedAt: request.CompletedAt,
		Status: request.Status, State: request.State, Upstream: request.Upstream,
		AppSelector: request.AppSelector, Model: request.Model, Method: request.Method,
		Path: request.Path, RequestBytes: request.RequestBytes, ResponseBytes: request.ResponseBytes,
		TokenInput: request.TokenInput, TokenOutput: request.TokenOutput,
		TokenCacheRead: request.TokenCacheRead, TokenCacheWrite: request.TokenCacheWrite,
		TokenTotal: request.TokenTotal,
	}
}

func (r statsRecord) entry() *statsEntry {
	return &statsEntry{
		sessionID: r.SessionID, started: r.StartedAt, completed: r.CompletedAt,
		status: r.Status, state: r.State, upstream: r.Upstream, selector: r.AppSelector,
		model: r.Model, method: r.Method, path: r.Path,
		reqBytes: r.RequestBytes, respBytes: r.ResponseBytes,
		tokens: tokenUsage{
			InputTokens: r.TokenInput, OutputTokens: r.TokenOutput,
			CacheReadTokens: r.TokenCacheRead, CacheWriteTokens: r.TokenCacheWrite,
			TotalTokens: r.TokenTotal, Seen: r.TokenTotal > 0 || r.TokenInput > 0 || r.TokenOutput > 0,
		},
		isError: r.Status >= 400 || errorState(r.State),
	}
}

// loadStatsHistory opens the append-only stats log under dir and restores the
// in-memory history from it. When no stats log exists yet (first boot after an
// upgrade, or a deleted stats file), the persisted session journal is
// backfilled instead so historical data is not lost.
func (h *sessionHub) loadStatsHistory(dir string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	path := filepath.Join(dir, "stats.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	h.statsFile = file
	data, readErr := os.ReadFile(path)
	if readErr != nil || len(data) == 0 {
		h.backfillStatsFromSessions()
		return
	}
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		var record statsRecord
		if json.Unmarshal([]byte(line), &record) != nil || record.StartedAt.IsZero() {
			continue
		}
		h.history = append(h.history, record.entry())
	}
}

// backfillStatsFromSessions seeds the stats history from persisted session
// files. It only runs when no stats log exists yet; seeded entries are written
// to the log so later restarts read a single authoritative source. Only
// requests that reached a terminal state are backfilled.
func (h *sessionHub) backfillStatsFromSessions() {
	entries, err := os.ReadDir(filepath.Join(h.sessionDir, "sessions"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.sessionDir, "sessions", entry.Name()))
		if err != nil {
			continue
		}
		var record sessionRecord
		if json.Unmarshal(data, &record) != nil || record.ID == "" {
			continue
		}
		for _, request := range record.Requests {
			if request.StartedAt.IsZero() || !isFinalState(request.State) {
				continue
			}
			h.syncStatsEntry(record.ID, request)
			h.persistStatsEntryLocked(record.ID, request)
		}
	}
}

// persistStatsEntryLocked appends one JSON line for a completed request to the
// stats log. It must be called with h.mu held.
func (h *sessionHub) persistStatsEntryLocked(sessionID string, request *sessionRequest) {
	if h.statsFile == nil {
		return
	}
	line, err := json.Marshal(statsRecordFromRequest(sessionID, request))
	if err != nil {
		return
	}
	_, _ = h.statsFile.Write(append(line, '\n'))
}

func makeStatsEntry(sessionID string, request *sessionRequest) *statsEntry {
	entry := &statsEntry{sessionID: sessionID}
	updateStatsEntry(entry, request)
	return entry
}

// updateStatsEntry refreshes an in-memory stats entry from the live request,
// so streaming requests keep their counters and final state current.
func updateStatsEntry(entry *statsEntry, request *sessionRequest) {
	entry.started = request.StartedAt
	entry.completed = request.CompletedAt
	entry.status = request.Status
	entry.state = request.State
	entry.upstream = request.Upstream
	entry.selector = request.AppSelector
	entry.model = request.Model
	entry.method = request.Method
	entry.path = request.Path
	entry.reqBytes = request.RequestBytes
	entry.respBytes = request.ResponseBytes
	entry.tokens = tokenUsage{
		InputTokens: request.TokenInput, OutputTokens: request.TokenOutput,
		CacheReadTokens: request.TokenCacheRead, CacheWriteTokens: request.TokenCacheWrite,
		TotalTokens: request.TokenTotal, Seen: request.HasTokenUsage,
	}
	entry.isError = request.Status >= 400 || errorState(request.State)
}

func (h *sessionHub) stats(window string) statsView {
	if !validStatsWindow(window) {
		window = "all"
	}
	cutoff := statsCutoff(window)
	h.mu.Lock()
	entries := make([]statsEntry, 0, len(h.history))
	sessions := make(map[string]struct{})
	for _, entry := range h.history {
		if !cutoff.IsZero() && entry.started.Before(cutoff) {
			continue
		}
		entries = append(entries, *entry)
		if entry.sessionID != "" {
			sessions[entry.sessionID] = struct{}{}
		}
	}
	pricing := append([]PricingRule(nil), h.pricing...)
	h.mu.Unlock()

	view := statsView{Sessions: int64(len(sessions)), Empty: len(entries) == 0, Window: window, Windows: windowOptions(window), HasCost: len(pricing) > 0}
	if len(entries) == 0 {
		return view
	}

	// Totals, traffic, latency, tokens and cost. Cost is estimated here from
	// the current pricing table (per entry, at render time) so later pricing
	// edits apply retroactively to the whole history.
	var totalReqBytes, totalRespBytes int64
	var totalTokens, totalInput, totalOutput, totalCacheRead, totalCacheWrite, tokenRequests int64
	var totalCost float64
	durations := make([]time.Duration, 0, len(entries))
	for i := range entries {
		entry := &entries[i]
		view.Requests++
		if entry.isError {
			view.Errors++
		}
		totalReqBytes += entry.reqBytes
		totalRespBytes += entry.respBytes
		if entry.tokens.Seen {
			tokenRequests++
			totalTokens += entry.tokens.total()
			totalInput += entry.tokens.InputTokens
			totalOutput += entry.tokens.OutputTokens
			totalCacheRead += entry.tokens.CacheReadTokens
			totalCacheWrite += entry.tokens.CacheWriteTokens
		}
		entry.cost = pricingCost(pricing, entry.model, entry.tokens)
		totalCost += entry.cost
		if !entry.completed.IsZero() && entry.completed.After(entry.started) {
			durations = append(durations, entry.completed.Sub(entry.started))
		}
	}
	view.InBytes = formatBytes64(totalReqBytes)
	view.OutBytes = formatBytes64(totalRespBytes)
	view.ErrorRate = percentString(view.Errors, view.Requests)
	if len(durations) > 0 {
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		var sum time.Duration
		for _, duration := range durations {
			sum += duration
		}
		view.AvgDuration = formatDuration(time.Duration(int64(sum) / int64(len(durations))))
		index := int(math.Ceil(0.95*float64(len(durations)))) - 1
		if index < 0 {
			index = 0
		}
		view.P95Duration = formatDuration(durations[index])
		view.MaxDuration = formatDuration(durations[len(durations)-1])
	}
	if view.HasCost {
		view.Cost = formatCost(totalCost)
	}
	if tokenRequests > 0 {
		view.HasTokens = true
		view.TotalTokens = compactCount(totalTokens)
		view.InputTokens = compactCount(totalInput)
		view.OutputTokens = compactCount(totalOutput)
		view.CacheReadTokens = compactCount(totalCacheRead)
		view.CacheWriteTokens = compactCount(totalCacheWrite)
		inOut := totalInput + totalOutput
		view.InputPct = percentString(totalInput, inOut)
		view.OutputPct = percentString(totalOutput, inOut)
	}

	view.Buckets, view.SpanLabel, view.BucketLabel = bucketSeries(entries)
	for _, bucket := range view.Buckets {
		if bucket.Count > view.MaxBucket {
			view.MaxBucket = bucket.Count
		}
	}
	view.Statuses = statusBreakdown(entries)
	view.States = stateBreakdown(entries)
	view.Upstreams = nameBreakdown(entries, func(e statsEntry) string { return e.upstream }, "未记录")
	view.Selectors = nameBreakdown(entries, func(e statsEntry) string { return e.selector }, "未匹配")
	view.Models = nameBreakdown(entries, func(e statsEntry) string { return e.model }, "未知模型")
	view.Methods = nameBreakdown(entries, func(e statsEntry) string { return e.method }, "未知方法")
	view.TopPaths = topPaths(entries)
	view.UpstreamRows = upstreamRows(entries)
	view.Daily = dailyRows(entries)
	view.ModelRows = modelRows(entries)
	view.SeriesJSON = buildSeriesJSON(entries, view.Buckets, view.Statuses, fmt.Sprintf("%s · 每%s聚合 · 峰值 %d 请求", view.SpanLabel, view.BucketLabel, view.MaxBucket))
	return view
}

// bucketSeries splits the request timeline into fixed-width buckets whose size
// adapts to the overall span, so the chart always has a readable shape. It also
// returns human-readable labels for the covered span and the granularity.
func bucketSeries(entries []statsEntry) ([]statsBucket, string, string) {
	var minTime, maxTime time.Time
	for _, entry := range entries {
		if minTime.IsZero() || entry.started.Before(minTime) {
			minTime = entry.started
		}
		if entry.started.After(maxTime) {
			maxTime = entry.started
		}
	}
	if minTime.IsZero() {
		return nil, "", ""
	}
	span := maxTime.Sub(minTime)
	width, labelLayout, bucketLabel := pickBucketWidth(span)
	spanLabel := ""
	switch {
	case span < time.Hour:
		spanLabel = fmt.Sprintf("跨度 %d 分钟", int(span/time.Minute)+1)
	case span < 24*time.Hour:
		spanLabel = fmt.Sprintf("跨度 %.1f 小时", span.Hours())
	default:
		spanLabel = fmt.Sprintf("跨度 %.1f 天", span.Hours()/24)
	}
	count := int(span/width) + 1
	buckets := make([]statsBucket, count)
	bucketDurations := make([][]time.Duration, count)
	maxCount := int64(0)
	for _, entry := range entries {
		index := int(entry.started.Sub(minTime) / width)
		if index < 0 {
			index = 0
		}
		if index >= count {
			index = count - 1
		}
		buckets[index].Count++
		if entry.isError {
			buckets[index].Errors++
		}
		if entry.tokens.Seen {
			buckets[index].InTok += entry.tokens.InputTokens
			buckets[index].OutTok += entry.tokens.OutputTokens
		}
		if !entry.completed.IsZero() && entry.completed.After(entry.started) {
			bucketDurations[index] = append(bucketDurations[index], entry.completed.Sub(entry.started))
		}
		if buckets[index].Count > maxCount {
			maxCount = buckets[index].Count
		}
	}
	labelStep := (count + 7) / 8
	if labelStep < 1 {
		labelStep = 1
	}
	for index := range buckets {
		bucket := &buckets[index]
		bucketTime := minTime.Add(time.Duration(index) * width)
		bucket.Unix = bucketTime.Unix()
		bucket.Time = bucketTime.Format(labelLayout)
		if index%labelStep == 0 || index == count-1 {
			bucket.Label = bucket.Time
		}
		if bucket.Count > 0 {
			bucket.H = barHeight(bucket.Count, maxCount)
		}
		if bucket.Errors > 0 {
			bucket.EH = barHeight(bucket.Errors, maxCount)
		}
		if bucket.Count > 0 && len(bucketDurations[index]) > 0 {
			bucket.AvgMs, bucket.P50Ms, bucket.P95Ms = bucketLatency(bucketDurations[index])
		}
	}
	return buckets, spanLabel, bucketLabel
}

// bucketLatency summarizes the durations of one bucket as average, p50 and
// p95 in milliseconds; percentiles use nearest-rank on the sorted list.
func bucketLatency(durations []time.Duration) (avgMs, p50Ms, p95Ms float64) {
	if len(durations) == 0 {
		return 0, 0, 0
	}
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, duration := range sorted {
		sum += duration
	}
	avgMs = float64(sum) / float64(len(sorted)) / float64(time.Millisecond)
	p50 := nearestRankPercentile(sorted, 0.5)
	p95 := nearestRankPercentile(sorted, 0.95)
	return avgMs, float64(p50) / float64(time.Millisecond), float64(p95) / float64(time.Millisecond)
}

// nearestRankPercentile returns the duration at the p-th percentile of an
// already-sorted list (clamped to the last element).
func nearestRankPercentile(sorted []time.Duration, p float64) time.Duration {
	index := int(math.Ceil(p*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	return sorted[index]
}

// pickBucketWidth selects a bucket width from a ladder so that at most ~96
// bars are drawn; the label layout and human granularity name follow.
func pickBucketWidth(span time.Duration) (time.Duration, string, string) {
	ladder := []struct {
		width  time.Duration
		layout string
		label  string
	}{
		{time.Minute, "15:04", "分钟"},
		{5 * time.Minute, "15:04", "5 分钟"},
		{15 * time.Minute, "15:04", "15 分钟"},
		{time.Hour, "15:04", "小时"},
		{6 * time.Hour, "01-02 15:04", "6 小时"},
		{24 * time.Hour, "01-02", "天"},
	}
	for _, step := range ladder {
		if span/step.width < 96 {
			return step.width, step.layout, step.label
		}
	}
	days := int(span/(24*time.Hour))/96 + 1
	return time.Duration(days) * 24 * time.Hour, "01-02", "天"
}

func statusBreakdown(entries []statsEntry) []statsBar {
	classes := []struct {
		name  string
		class string
	}{
		{"2xx 成功", "status-2xx"},
		{"3xx 重定向", "status-3xx"},
		{"4xx 客户端错误", "status-4xx"},
		{"5xx 服务端错误", "status-5xx"},
	}
	counts := map[string]int64{"2xx 成功": 0, "3xx 重定向": 0, "4xx 客户端错误": 0, "5xx 服务端错误": 0}
	for _, entry := range entries {
		switch {
		case entry.status >= 500:
			counts["5xx 服务端错误"]++
		case entry.status >= 400:
			counts["4xx 客户端错误"]++
		case entry.status >= 300:
			counts["3xx 重定向"]++
		default:
			counts["2xx 成功"]++
		}
	}
	names := make([]string, 0, len(classes))
	for _, class := range classes {
		if counts[class.name] > 0 {
			names = append(names, class.name)
		}
	}
	return makeBars(names, counts, int64(len(entries)), func(name string) string {
		for _, class := range classes {
			if class.name == name {
				return class.class
			}
		}
		return ""
	})
}

func stateBreakdown(entries []statsEntry) []statsBar {
	labels := map[string]string{
		"completed":     "完成",
		"client closed": "客户端断开",
		"timed out":     "超时",
		"interrupted":   "中断",
	}
	classes := map[string]string{
		"completed":     "is-completed",
		"client closed": "is-warning", "timed out": "is-error", "interrupted": "is-error",
	}
	counts := make(map[string]int64)
	for _, entry := range entries {
		name := labels[entry.state]
		if name == "" {
			name = entry.state
		}
		counts[name]++
	}
	return makeBars(sortedNames(counts), counts, int64(len(entries)), func(name string) string {
		for state, label := range labels {
			if label == name {
				return classes[state]
			}
		}
		return ""
	})
}

// nameBreakdown aggregates entries by a dimension (upstream, selector, model,
// method), keeps the top statsTopN and folds the remainder into one "其他" row.
func nameBreakdown(entries []statsEntry, pick func(statsEntry) string, emptyLabel string) []statsBar {
	counts := make(map[string]int64)
	for _, entry := range entries {
		name := pick(entry)
		if name == "" {
			name = emptyLabel
		}
		counts[name]++
	}
	return makeBars(sortedNames(counts), counts, int64(len(entries)), nil)
}

// statsUpstreamRow is one row of the per-upstream summary table, sorted by
// request volume so the busiest upstreams surface first.
type statsUpstreamRow struct {
	Name      string
	Requests  int64
	Errors    int64
	ErrorRate string
	InBytes   string
	OutBytes  string
	Avg       string
	Cost      string
}

// upstreamRows aggregates requests per upstream into a compact comparison
// table (volume, error rate, traffic, average latency, estimated cost).
func upstreamRows(entries []statsEntry) []statsUpstreamRow {
	type agg struct {
		requests, errors, inBytes, outBytes int64
		durations                           []time.Duration
		cost                                float64
	}
	groups := make(map[string]*agg)
	for _, entry := range entries {
		name := entry.upstream
		if name == "" {
			name = "未记录"
		}
		group := groups[name]
		if group == nil {
			group = &agg{}
			groups[name] = group
		}
		group.requests++
		if entry.isError {
			group.errors++
		}
		group.inBytes += entry.reqBytes
		group.outBytes += entry.respBytes
		group.cost += entry.cost
		if !entry.completed.IsZero() && entry.completed.After(entry.started) {
			group.durations = append(group.durations, entry.completed.Sub(entry.started))
		}
	}
	rows := make([]statsUpstreamRow, 0, len(groups))
	for name, group := range groups {
		row := statsUpstreamRow{
			Name:      name,
			Requests:  group.requests,
			Errors:    group.errors,
			ErrorRate: percentString(group.errors, group.requests),
			InBytes:   formatBytes64(group.inBytes),
			OutBytes:  formatBytes64(group.outBytes),
			Cost:      formatCost(group.cost),
		}
		if len(group.durations) > 0 {
			var sum time.Duration
			for _, duration := range group.durations {
				sum += duration
			}
			row.Avg = formatDuration(time.Duration(int64(sum) / int64(len(group.durations))))
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Requests != rows[j].Requests {
			return rows[i].Requests > rows[j].Requests
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

func makeBars(names []string, counts map[string]int64, total int64, classFor func(string) string) []statsBar {
	names = append([]string(nil), names...)
	sort.Slice(names, func(i, j int) bool { return counts[names[i]] > counts[names[j]] })
	if len(names) > statsTopN {
		names = names[:statsTopN]
	}
	kept := names
	var others int64
	for _, name := range sortedNames(counts) {
		if !stringSliceContains(kept, name) {
			others += counts[name]
		}
	}
	if others > 0 {
		names = append(names, "其他")
		counts["其他"] = others
	}
	maxCount := int64(0)
	for _, name := range names {
		if counts[name] > maxCount {
			maxCount = counts[name]
		}
	}
	bars := make([]statsBar, 0, len(names))
	for _, name := range names {
		count := counts[name]
		class := ""
		if classFor != nil {
			class = classFor(name)
		}
		bars = append(bars, statsBar{Name: name, Count: count, Pct: percentString(count, total), H: barHeight(count, maxCount), Class: class})
	}
	return bars
}

func topPaths(entries []statsEntry) []statsPath {
	type pathKey struct {
		method, path string
	}
	counts := make(map[pathKey]int64)
	for _, entry := range entries {
		if entry.path == "" {
			continue
		}
		counts[pathKey{entry.method, entry.path}]++
	}
	keys := make([]pathKey, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return counts[keys[i]] > counts[keys[j]] })
	if len(keys) > statsTopN {
		keys = keys[:statsTopN]
	}
	paths := make([]statsPath, 0, len(keys))
	for _, key := range keys {
		paths = append(paths, statsPath{Method: key.method, Path: key.path, Count: counts[key]})
	}
	return paths
}

func sortedNames(counts map[string]int64) []string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// statsSeries is the structured chart payload embedded in the stats fragment
// and consumed by the browser-side lightweight-charts / Chart.js renderers.
type statsSeries struct {
	Buckets  []statsSeriesBucket `json:"buckets"`
	Heatmap  []statsHeatCell     `json:"heatmap"`
	Statuses []statsSeriesStatus `json:"statuses"`
	Tokens   bool                `json:"tokens"`
	Meta     string              `json:"meta"`
}

type statsSeriesBucket struct {
	Time   int64   `json:"t"`
	Count  int64   `json:"count"`
	Errors int64   `json:"errors"`
	AvgMs  float64 `json:"avg,omitempty"`
	P50Ms  float64 `json:"p50,omitempty"`
	P95Ms  float64 `json:"p95,omitempty"`
	InTok  int64   `json:"in,omitempty"`
	OutTok int64   `json:"out,omitempty"`
}

type statsSeriesStatus struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// statsHeatCell is one non-empty hour-of-day × weekday cell of the activity
// heatmap; day follows time.Weekday (0 = Sunday), matching the chart labels.
type statsHeatCell struct {
	Hour  int   `json:"hour"`
	Day   int   `json:"day"`
	Count int64 `json:"count"`
}

func buildSeriesJSON(entries []statsEntry, buckets []statsBucket, statuses []statsBar, meta string) string {
	series := statsSeries{
		Buckets:  make([]statsSeriesBucket, 0, len(buckets)),
		Heatmap:  heatmapCells(entries),
		Statuses: make([]statsSeriesStatus, 0, len(statuses)),
		Meta:     meta,
	}
	for _, bucket := range buckets {
		if bucket.InTok > 0 || bucket.OutTok > 0 {
			series.Tokens = true
		}
		series.Buckets = append(series.Buckets, statsSeriesBucket{Time: bucket.Unix, Count: bucket.Count, Errors: bucket.Errors, AvgMs: bucket.AvgMs, P50Ms: bucket.P50Ms, P95Ms: bucket.P95Ms, InTok: bucket.InTok, OutTok: bucket.OutTok})
	}
	for _, status := range statuses {
		series.Statuses = append(series.Statuses, statsSeriesStatus{Name: status.Name, Count: status.Count})
	}
	data, err := json.Marshal(series)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// heatmapCells aggregates requests into the hour-of-day × weekday grid. The
// grid is keyed by UTC hour/day so the browser can shift it into the user's
// own timezone (the dashboard may run on a UTC host while the operator is in
// another zone); this mirrors the activity heatmap of the reference dashboard.
func heatmapCells(entries []statsEntry) []statsHeatCell {
	counts := make(map[[2]int]int64)
	for _, entry := range entries {
		if entry.started.IsZero() {
			continue
		}
		utc := entry.started.UTC()
		counts[[2]int{utc.Hour(), int(utc.Weekday())}]++
	}
	cells := make([]statsHeatCell, 0, len(counts))
	for key, count := range counts {
		cells = append(cells, statsHeatCell{Hour: key[0], Day: key[1], Count: count})
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].Day != cells[j].Day {
			return cells[i].Day < cells[j].Day
		}
		return cells[i].Hour < cells[j].Hour
	})
	return cells
}

// statsDailyRow is one row of the per-day usage table, rendered server side.
type statsDailyRow struct {
	Date     string
	Requests int64
	Errors   int64
	InBytes  string
	OutBytes string
	Avg      string
	Cost     string
}

// dailyRows groups requests by local calendar day and keeps the most recent
// days, newest first.
func dailyRows(entries []statsEntry) []statsDailyRow {
	type dayAgg struct {
		requests, errors, inBytes, outBytes int64
		durations                           []time.Duration
		cost                                float64
	}
	days := make(map[string]*dayAgg)
	for _, entry := range entries {
		if entry.started.IsZero() {
			continue
		}
		day := entry.started.Local().Format("2006-01-02")
		agg := days[day]
		if agg == nil {
			agg = &dayAgg{}
			days[day] = agg
		}
		agg.requests++
		if entry.isError {
			agg.errors++
		}
		agg.inBytes += entry.reqBytes
		agg.outBytes += entry.respBytes
		agg.cost += entry.cost
		if !entry.completed.IsZero() && entry.completed.After(entry.started) {
			agg.durations = append(agg.durations, entry.completed.Sub(entry.started))
		}
	}
	order := make([]string, 0, len(days))
	for day := range days {
		order = append(order, day)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(order)))
	if len(order) > 30 {
		order = order[:30]
	}
	rows := make([]statsDailyRow, 0, len(order))
	for _, day := range order {
		agg := days[day]
		avg := "-"
		if len(agg.durations) > 0 {
			var sum time.Duration
			for _, duration := range agg.durations {
				sum += duration
			}
			avg = formatDuration(time.Duration(int64(sum) / int64(len(agg.durations))))
		}
		rows = append(rows, statsDailyRow{Date: day, Requests: agg.requests, Errors: agg.errors, InBytes: formatBytes64(agg.inBytes), OutBytes: formatBytes64(agg.outBytes), Avg: avg, Cost: formatCost(agg.cost)})
	}
	return rows
}

// statsModelRow is one row of the per-model token usage table: request volume
// plus the prompt/completion token split and estimated cost.
type statsModelRow struct {
	Name         string
	Requests     int64
	InputTokens  string
	OutputTokens string
	TotalTokens  string
	Cost         string
}

// modelRows aggregates token usage per model, keeps the top statsTopN by total
// tokens and folds the rest into one "其他" row so the table stays readable.
func modelRows(entries []statsEntry) []statsModelRow {
	type modelAgg struct {
		requests, input, output int64
		cost                    float64
	}
	groups := make(map[string]*modelAgg)
	for _, entry := range entries {
		name := entry.model
		if name == "" {
			name = "未知模型"
		}
		group := groups[name]
		if group == nil {
			group = &modelAgg{}
			groups[name] = group
		}
		group.requests++
		group.input += entry.tokens.InputTokens
		group.output += entry.tokens.OutputTokens
		group.cost += entry.cost
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		if groups[name].input+groups[name].output > 0 {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		left := groups[names[i]].input + groups[names[i]].output
		right := groups[names[j]].input + groups[names[j]].output
		if left != right {
			return left > right
		}
		return names[i] < names[j]
	})
	if len(names) > statsTopN {
		names = names[:statsTopN]
	}
	kept := make(map[string]bool, len(names))
	for _, name := range names {
		kept[name] = true
	}
	var other modelAgg
	for name, group := range groups {
		if !kept[name] {
			other.requests += group.requests
			other.input += group.input
			other.output += group.output
			other.cost += group.cost
		}
	}
	rows := make([]statsModelRow, 0, len(names)+1)
	for _, name := range names {
		group := groups[name]
		rows = append(rows, statsModelRow{
			Name:         name,
			Requests:     group.requests,
			InputTokens:  compactCount(group.input),
			OutputTokens: compactCount(group.output),
			TotalTokens:  compactCount(group.input + group.output),
			Cost:         formatCost(group.cost),
		})
	}
	if other.input+other.output > 0 {
		rows = append(rows, statsModelRow{
			Name:         "其他",
			Requests:     other.requests,
			InputTokens:  compactCount(other.input),
			OutputTokens: compactCount(other.output),
			TotalTokens:  compactCount(other.input + other.output),
			Cost:         formatCost(other.cost),
		})
	}
	return rows
}

// compactCount abbreviates large counts like the reference dashboard's
// formatCompact: 12345 becomes 12.3k, 2500000 becomes 2.5M.
func compactCount(count int64) string {
	switch {
	case count >= 1000000:
		return fmt.Sprintf("%.1fM", float64(count)/1000000)
	case count >= 1000:
		return fmt.Sprintf("%.1fk", float64(count)/1000)
	default:
		return fmt.Sprintf("%d", count)
	}
}

func percentString(part, total int64) string {
	if total == 0 {
		return "0%"
	}
	percent := float64(part) / float64(total) * 100
	if percent > 0 && percent < 0.1 {
		return "<0.1%"
	}
	if percent >= 100 {
		return "100%"
	}
	digits := 0
	if percent < 10 {
		digits = 1
	}
	return strconv.FormatFloat(percent, 'f', digits, 64) + "%"
}

// formatDuration renders a duration the same way session timings are shown:
// milliseconds below one second, seconds and up beyond that.
func formatDuration(duration time.Duration) string {
	return duration.Round(time.Millisecond).String()
}

// barHeight maps a count to a 4-100% bar height, keeping tiny values visible.
func barHeight(count, maxCount int64) int {
	if maxCount <= 0 || count <= 0 {
		return 0
	}
	height := int(float64(count) / float64(maxCount) * 100)
	if height < 4 {
		height = 4
	}
	if height > 100 {
		height = 100
	}
	return height
}

func (p *Proxy) serveStats(w http.ResponseWriter, r *http.Request) {
	if p.Sessions == nil {
		http.Error(w, "session tracking is unavailable", http.StatusServiceUnavailable)
		return
	}
	window := r.URL.Query().Get("window")
	content, err := renderStats(p.Sessions.stats(window))
	if err != nil {
		http.Error(w, "failed to render stats", http.StatusInternalServerError)
		return
	}
	if r.URL.Path == "/stats" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, content)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported", http.StatusInternalServerError)
		return
	}
	client := p.Sessions.subscribe()
	defer p.Sessions.unsubscribe(client)
	for {
		content, err := renderStats(p.Sessions.stats(window))
		if err != nil || writeNamedSSE(w, "stats", content) != nil {
			return
		}
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-client:
		}
	}
}

func renderStats(view statsView) (string, error) {
	var output bytes.Buffer
	if err := getTemplate("stats.html").Execute(&output, view); err != nil {
		return "", err
	}
	return output.String(), nil
}

// statsExportWindows are the windows inlined into a standalone snapshot; the
// exported page keeps its window buttons working without the gateway.
var statsExportWindows = []string{"all", "1h", "24h", "7d", "30d"}

func (p *Proxy) serveStatsExport(w http.ResponseWriter, r *http.Request) {
	if p.Sessions == nil {
		http.Error(w, "session tracking is unavailable", http.StatusServiceUnavailable)
		return
	}
	html, err := buildStatsSnapshotHTML(p.Sessions)
	if err != nil {
		http.Error(w, "failed to render stats snapshot", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="agw-stats-`+time.Now().Format("20060102-1504")+`.html"`)
	_, _ = io.WriteString(w, html)
}

// buildStatsSnapshotHTML assembles a fully standalone snapshot of the stats
// tab: the page's own stylesheet, the stable stats-panel markup and the chart
// JavaScript (extracted between the markers, byte for byte identical to the
// live page) with every window's fragment inlined as STATS_WINDOWS. The
// result is a single HTML file that renders charts from the CDN and needs no
// gateway, so it can be shared or archived.
func buildStatsSnapshotHTML(hub *sessionHub) (string, error) {
	raw, err := templateFS.ReadFile("templates/page.html")
	if err != nil {
		return "", err
	}
	page := string(raw)

	styleStart := strings.Index(page, "<style>")
	styleEnd := strings.Index(page, "</style>")
	if styleStart < 0 || styleEnd < styleStart {
		return "", fmt.Errorf("page template: style block not found")
	}
	style := page[styleStart+len("<style>") : styleEnd]

	panelLine := ""
	for _, line := range strings.Split(page, "\n") {
		if strings.Contains(line, `id="stats-panel"`) {
			panelLine = line
			break
		}
	}
	if panelLine == "" {
		return "", fmt.Errorf("page template: stats panel not found")
	}
	panel := panelLine[strings.Index(panelLine, `<div class="telemetry-panel" id="stats-panel"`):]
	panel = strings.Replace(panel, `id="stats-panel" role="tabpanel" aria-labelledby="stats-tab" hidden`, `id="stats-panel" role="tabpanel" aria-labelledby="stats-tab"`, 1)

	const startMarker = "// ==== stats charts start ===="
	const endMarker = "// ==== stats charts end ===="
	chartStart := strings.Index(page, startMarker)
	chartEnd := strings.Index(page, endMarker)
	if chartStart < 0 || chartEnd < chartStart {
		return "", fmt.Errorf("page template: chart block markers not found")
	}
	chartJS := strings.TrimRight(page[chartStart:chartEnd], " \t\r\n") + "\n"

	var windows strings.Builder
	windows.WriteString("{\n")
	for i, key := range statsExportWindows {
		if i > 0 {
			windows.WriteString(",\n")
		}
		fragment, err := renderStats(hub.stats(key))
		if err != nil {
			return "", err
		}
		encoded, err := json.Marshal(fragment)
		if err != nil {
			return "", err
		}
		windows.WriteString("  " + strconv.Quote(key) + ": " + string(encoded))
	}
	windows.WriteString("\n}")

	// Mirrors the static preview shell so exports look identical to it; the
	// chart block below expects setTheme/destroyStatsCharts/renderStatsCharts.
	shellJS := `const themeToggle = document.getElementById('theme-toggle');
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('agw-theme', theme); } catch (_) {}
  const isDark = theme === 'dark';
  themeToggle.title = isDark ? '切换到浅色主题' : '切换到深色主题';
  themeToggle.setAttribute('aria-label', themeToggle.title);
  themeToggle.innerHTML = '<i data-lucide="' + (isDark ? 'sun' : 'moon') + '"></i>';
  renderIcons(themeToggle);
  destroyStatsCharts(); renderStatsCharts();
}
themeToggle.addEventListener('click', function () {
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});
setTheme(document.documentElement.dataset.theme || 'light');
`

	const shell = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AGW Stats 快照</title>
  <meta name="theme-color" content="#12312d">
  <script>try { document.documentElement.dataset.theme = localStorage.getItem('agw-theme') || 'light'; } catch (_) { document.documentElement.dataset.theme = 'light'; }</script>
  <script src="https://unpkg.com/lucide@0.468.0"></script>
  <script src="https://unpkg.com/lightweight-charts@4.2.0/dist/lightweight-charts.standalone.production.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
__STYLE__
  </style>
</head>
<body>
  <main class="shell">
    <section class="telemetry" aria-labelledby="workspace-title">
      <h2 class="sr-only" id="workspace-title">Workspace</h2>
      <div class="telemetry-top">
        <div class="identity">
          <div class="brand-mark" title="AGW">AGW</div>
        </div>
        <div class="telemetry-tabbar" role="tablist" aria-label="工作区视图"><button class="telemetry-tab" type="button" role="tab" aria-selected="true"><span class="live-dot"></span><span>Stats</span></button></div>
        <div class="appbar-actions">
          <span id="status" aria-live="polite">静态快照 · 导出于 __EXPORTED__</span>
          <button class="icon-button" type="button" id="theme-toggle" title="切换到浅色主题" aria-label="切换到浅色主题"><i data-lucide="sun"></i></button>
        </div>
      </div>
__PANEL__
    </section>
  </main>
  <script>
const STATS_WINDOWS = __WINDOWS_JSON__;
function renderIcons(scope) { if (window.lucide) window.lucide.createIcons({root: scope || document, attrs: {'stroke-width': 1.8}}); }
__CHART_JS__
  </script>
  <script>
__SHELL_JS__
  </script>
</body>
</html>
`
	out := strings.Replace(shell, "__STYLE__", style, 1)
	out = strings.Replace(out, "__PANEL__", panel, 1)
	out = strings.Replace(out, "__WINDOWS_JSON__", windows.String(), 1)
	out = strings.Replace(out, "__CHART_JS__", chartJS, 1)
	out = strings.Replace(out, "__SHELL_JS__", shellJS, 1)
	out = strings.Replace(out, "__EXPORTED__", time.Now().Format("2006-01-02 15:04"), 1)
	return out, nil
}
