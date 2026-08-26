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
	Requests    int64
	Sessions    int
	Errors      int64
	ErrorRate   string
	InBytes     string
	OutBytes    string
	AvgDuration string
	P95Duration string
	MaxDuration string
	SpanLabel   string
	BucketLabel string
	MaxBucket   int64
	Buckets     []statsBucket
	Statuses    []statsBar
	States      []statsBar
	Upstreams   []statsBar
	Selectors   []statsBar
	Models      []statsBar
	Methods     []statsBar
	TopPaths    []statsPath
	Window      string
	Windows     []statsWindow
	Empty       bool
}

type statsWindow struct {
	Key    string
	Label  string
	Active bool
}

type statsBucket struct {
	Label  string
	Time   string
	Count  int64
	Errors int64
	H      int
	EH     int
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
	isError   bool
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
	SessionID     string    `json:"SessionID"`
	StartedAt     time.Time `json:"StartedAt"`
	CompletedAt   time.Time `json:"CompletedAt"`
	Status        int       `json:"Status"`
	State         string    `json:"State"`
	Upstream      string    `json:"Upstream,omitempty"`
	AppSelector   string    `json:"AppSelector,omitempty"`
	Model         string    `json:"Model,omitempty"`
	Method        string    `json:"Method,omitempty"`
	Path          string    `json:"Path,omitempty"`
	RequestBytes  int64     `json:"RequestBytes,omitempty"`
	ResponseBytes int64     `json:"ResponseBytes,omitempty"`
}

func statsRecordFromRequest(sessionID string, request *sessionRequest) statsRecord {
	return statsRecord{
		SessionID: sessionID, StartedAt: request.StartedAt, CompletedAt: request.CompletedAt,
		Status: request.Status, State: request.State, Upstream: request.Upstream,
		AppSelector: request.AppSelector, Model: request.Model, Method: request.Method,
		Path: request.Path, RequestBytes: request.RequestBytes, ResponseBytes: request.ResponseBytes,
	}
}

func (r statsRecord) entry() *statsEntry {
	return &statsEntry{
		sessionID: r.SessionID, started: r.StartedAt, completed: r.CompletedAt,
		status: r.Status, state: r.State, upstream: r.Upstream, selector: r.AppSelector,
		model: r.Model, method: r.Method, path: r.Path,
		reqBytes: r.RequestBytes, respBytes: r.ResponseBytes,
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
	h.mu.Unlock()

	view := statsView{Sessions: len(sessions), Empty: len(entries) == 0, Window: window, Windows: windowOptions(window)}
	if len(entries) == 0 {
		return view
	}

	// Totals, traffic and latency.
	var totalReqBytes, totalRespBytes int64
	durations := make([]time.Duration, 0, len(entries))
	for _, entry := range entries {
		view.Requests++
		if entry.isError {
			view.Errors++
		}
		totalReqBytes += entry.reqBytes
		totalRespBytes += entry.respBytes
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
	}
	return buckets, spanLabel, bucketLabel
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
		{"处理中", "status-pending"},
	}
	counts := map[string]int64{"2xx 成功": 0, "3xx 重定向": 0, "4xx 客户端错误": 0, "5xx 服务端错误": 0, "处理中": 0}
	for _, entry := range entries {
		switch {
		case entry.status == 0:
			counts["处理中"]++
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
		"streaming":     "流式传输中",
		"connecting":    "连接中",
		"client closed": "客户端断开",
		"timed out":     "超时",
		"interrupted":   "中断",
	}
	classes := map[string]string{
		"completed": "is-completed", "streaming": "is-streaming", "connecting": "is-connecting",
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
