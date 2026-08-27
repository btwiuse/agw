package agw

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxSessionCards = 48
const maxRequestsPerSession = 8
const responsePreviewInterval = 150 * time.Millisecond

type sessionHeader struct {
	Name  string
	Value string
}

type sessionRequest struct {
	Sequence           uint64
	Method             string
	Path               string
	StartedAt          time.Time
	CompletedAt        time.Time
	Status             int
	State              string
	Bytes              int
	Headers            []sessionHeader
	ContentType        string
	LastPreview        time.Time
	RequestContentType string
	RequestBytes       int64
	ResponseBytes      int64
	RequestKey         string
	ResponseKey        string
	ResponsePayload    PayloadFile `json:"-"`
	AppSelector        string
	Upstream           string
	Model              string
	OriginalModel      string
	Events             []sessionEvent
}

type sessionEvent struct {
	At     time.Time
	Kind   string
	Detail string
}

type sessionRecord struct {
	ID           string
	FirstSeen    time.Time
	LastSeen     time.Time
	RequestCount int
	Requests     []*sessionRequest
}

type sessionHub struct {
	mu          sync.Mutex
	records     map[string]*sessionRecord
	subscribers map[chan struct{}]struct{}
	nextID      uint64
	payloads    PayloadStore
	sessionDir  string
	// history keeps one statsEntry per request this process has seen, plus
	// requests restored from the persisted stats log at startup. Unlike the
	// journal records it is never evicted, so stats aggregate everything
	// currently available instead of the recent-session window.
	history    []*statsEntry
	statsIndex map[uint64]int
	// statsFile appends one JSON line per completed request to data/stats.jsonl
	// so stats survive restarts; nil in non-persistent mode.
	statsFile *os.File
}

type trackedSession struct {
	hub       *sessionHub
	sessionID string
	sequence  uint64
}

type sessionCard struct {
	ID           string
	ShortID      string
	Started      string
	Duration     string
	State        string
	StateClass   string
	Status       string
	StatusClass  string
	RequestCount int
	AppSelector  string
	Upstream     string
	Latest       sessionRequestCard
	Requests     []sessionRequestCard
}

type sessionRequestCard struct {
	Method             string
	Path               string
	Started            string
	Duration           string
	State              string
	Status             string
	Bytes              string
	Headers            []sessionHeader
	ContentType        string
	RequestContentType string
	RequestBytes       string
	ResponseBytes      string
	AppSelector        string
	Upstream           string
	Model              string
	HasRequestBody     bool
	HasResponseBody    bool
	Events             []sessionEventCard
}

type sessionEventCard struct {
	At     string
	Kind   string
	Detail string
}

func newSessionHub() *sessionHub {
	return newSessionHubWith(FilePayloads())
}

// newSessionHubPersistent builds a session hub whose metadata and payloads
// survive restarts: records are written as JSON under dir/sessions, payload
// bodies live under dir/payloads and completed requests are appended to the
// stats log under dir/stats.jsonl. Existing data is loaded on startup.
func newSessionHubPersistent(dir string) *sessionHub {
	payloadDir := filepath.Join(dir, "payloads")
	hub := newSessionHubWith(FilePayloadsAt(payloadDir))
	hub.sessionDir = dir
	hub.loadStatsHistory(dir)
	if err := os.MkdirAll(filepath.Join(dir, "sessions"), 0755); err != nil {
		return hub
	}
	hub.loadRecords()
	return hub
}

func (h *sessionHub) recordPath(id string) string {
	return filepath.Join(h.sessionDir, "sessions", id+".json")
}

// saveRecordLocked persists a session record as JSON. It must be called with
// h.mu held.
func (h *sessionHub) saveRecordLocked(id string) {
	if h.sessionDir == "" {
		return
	}
	record := h.records[id]
	if record == nil {
		return
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	_ = os.WriteFile(h.recordPath(id), data, 0600)
}

func (h *sessionHub) deleteRecord(id string) {
	if h.sessionDir == "" {
		return
	}
	_ = os.Remove(h.recordPath(id))
}

// loadRecords restores persisted session metadata at startup. Payload bodies
// stay on disk and are reachable again through the stored request/response
// keys; the open write handles are not restored.
func (h *sessionHub) loadRecords() {
	entries, err := os.ReadDir(filepath.Join(h.sessionDir, "sessions"))
	if err != nil {
		return
	}
	var maxSequence uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.sessionDir, "sessions", entry.Name()))
		if err != nil {
			continue
		}
		var record sessionRecord
		if json.Unmarshal(data, &record) != nil || record.ID == "" || len(record.Requests) == 0 {
			continue
		}
		for _, request := range record.Requests {
			request.ResponsePayload = nil
			if request.Sequence > maxSequence {
				maxSequence = request.Sequence
			}
		}
		h.mu.Lock()
		h.records[record.ID] = &record
		h.mu.Unlock()
	}
	if maxSequence > h.nextID {
		h.nextID = maxSequence
	}
}

// newSessionHubWith builds a session hub backed by the given payload store.
// A js/wasm build can pass MemoryPayloads() so nothing touches the filesystem.
func newSessionHubWith(payloads PayloadStore) *sessionHub {
	return &sessionHub{records: make(map[string]*sessionRecord), subscribers: make(map[chan struct{}]struct{}), payloads: payloads, statsIndex: make(map[uint64]int)}
}

func (h *sessionHub) start(r *http.Request) *trackedSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.nextID++
	id := newSessionID(now, h.nextID)
	record := &sessionRecord{ID: id, FirstSeen: now}
	h.records[id] = record
	record.LastSeen = now
	record.RequestCount++
	request := &sessionRequest{Sequence: h.nextID, Method: r.Method, Path: r.URL.RequestURI(), StartedAt: now, State: "connecting", Headers: redactHeaders(r.Header)}
	if h.payloads != nil {
		key := id + "-" + fmt.Sprintf("%d", request.Sequence)
		request.RequestKey = key + ".request"
		request.ResponseKey = key + ".response"
		request.ResponsePayload, _ = h.payloads.Create(request.ResponseKey)
	}
	record.Requests = append(record.Requests, request)
	if len(record.Requests) > maxRequestsPerSession {
		pruned := record.Requests[:len(record.Requests)-maxRequestsPerSession]
		record.Requests = record.Requests[len(record.Requests)-maxRequestsPerSession:]
		h.removePayloads(pruned)
	}
	h.publishLocked()
	h.evictLocked()
	h.saveRecordLocked(id)
	return &trackedSession{hub: h, sessionID: id, sequence: request.Sequence}
}

// evictLocked drops the least recently seen records beyond maxSessionCards so
// the session map (and the on-disk payload files) cannot grow without bound.
func (h *sessionHub) evictLocked() {
	excess := len(h.records) - maxSessionCards
	for i := 0; i < excess; i++ {
		var oldestID string
		var oldest time.Time
		for id, record := range h.records {
			if oldestID == "" || record.LastSeen.Before(oldest) {
				oldestID = id
				oldest = record.LastSeen
			}
		}
		if oldestID == "" {
			return
		}
		record := h.records[oldestID]
		for _, request := range record.Requests {
			h.removePayloads([]*sessionRequest{request})
		}
		h.deleteRecord(oldestID)
		delete(h.records, oldestID)
	}
}

func (h *sessionHub) removePayloads(requests []*sessionRequest) {
	for _, request := range requests {
		if h.payloads == nil {
			continue
		}
		if request.ResponsePayload != nil {
			_ = request.ResponsePayload.Close()
			request.ResponsePayload = nil
		}
		_ = h.payloads.Remove(request.RequestKey)
		_ = h.payloads.Remove(request.ResponseKey)
	}
}

func (t *trackedSession) connected(status int) {
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.Status = status
		request.State = "streaming"
	})
}

func (t *trackedSession) setAppSelector(selector string) {
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.AppSelector = selector
	})
}

func (t *trackedSession) setUpstream(upstream string) {
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.Upstream = upstream
	})
}

func (t *trackedSession) setContentType(contentType string) {
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.ContentType = contentType
	})
}

func (t *trackedSession) setRequestBody(contentType string, body []byte) {
	key := t.hub.requestKey(t)
	var bytesWritten int64
	model := ""
	if len(body) > 0 && key != "" && t.hub.payloads != nil {
		if err := t.hub.payloads.WriteRequest(key, body); err == nil {
			bytesWritten = int64(len(body))
		}
	}
	if len(body) > 0 {
		model, _ = bodyFieldValue(body, "model")
	}
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.RequestContentType = contentType
		request.RequestBytes = bytesWritten
		request.Model = model
	})
}

func (t *trackedSession) setOriginalModel(model string) {
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.OriginalModel = model
	})
}

func (t *trackedSession) captureResponse(data []byte) {
	if len(data) == 0 {
		return
	}
	t.hub.captureResponse(t, data)
}

func (t *trackedSession) addEvent(kind, detail string) {
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.Events = append(request.Events, sessionEvent{At: time.Now(), Kind: kind, Detail: detail})
		if len(request.Events) > 24 {
			request.Events = request.Events[len(request.Events)-24:]
		}
	})
}

func (t *trackedSession) complete(status, bytes int, contextErr error) {
	t.hub.updateRequest(t, func(request *sessionRequest) {
		request.Status = status
		request.Bytes = bytes
		request.CompletedAt = time.Now()
		switch contextErr {
		case nil:
			request.State = "completed"
		case context.Canceled:
			request.State = "client closed"
		case context.DeadlineExceeded:
			request.State = "timed out"
		default:
			request.State = "interrupted"
		}
		if request.ResponsePayload != nil {
			_ = request.ResponsePayload.Close()
			request.ResponsePayload = nil
		}
	})
}

func (h *sessionHub) updateRequest(tracked *trackedSession, update func(*sessionRequest)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	record := h.records[tracked.sessionID]
	if record == nil {
		return
	}
	for _, request := range record.Requests {
		if request.Sequence == tracked.sequence {
			wasFinal := isFinalState(request.State)
			update(request)
			record.LastSeen = time.Now()
			if !wasFinal && isFinalState(request.State) {
				h.persistStatsEntryLocked(record.ID, request)
			}
			// Only completed requests enter the stats history; tracking the
			// in-flight state would repaint the dashboard on every streamed
			// chunk and make the UI jitter.
			if isFinalState(request.State) {
				h.syncStatsEntry(record.ID, request)
			}
			h.publishLocked()
			h.saveRecordLocked(tracked.sessionID)
			return
		}
	}
}

func (h *sessionHub) captureResponse(tracked *trackedSession, data []byte) {
	h.mu.Lock()
	record := h.records[tracked.sessionID]
	if record == nil {
		h.mu.Unlock()
		return
	}
	for _, request := range record.Requests {
		if request.Sequence != tracked.sequence {
			continue
		}
		request.Bytes += len(data)
		request.ResponseBytes += int64(len(data))
		record.LastSeen = time.Now()
		if isFinalState(request.State) {
			h.syncStatsEntry(record.ID, request)
		}
		payload := request.ResponsePayload
		shouldPublish := request.LastPreview.IsZero() || time.Since(request.LastPreview) >= responsePreviewInterval
		if shouldPublish {
			request.LastPreview = time.Now()
		}
		h.mu.Unlock()
		if payload != nil {
			_, _ = payload.Write(data)
		}
		h.mu.Lock()
		if shouldPublish {
			h.saveRecordLocked(tracked.sessionID)
			h.publishLocked()
		}
		h.mu.Unlock()
		return
	}
	h.mu.Unlock()
}

func (h *sessionHub) cards() []sessionCard {
	h.mu.Lock()
	defer h.mu.Unlock()
	records := make([]*sessionRecord, 0, len(h.records))
	for _, record := range h.records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].LastSeen.After(records[j].LastSeen) })
	if len(records) > maxSessionCards {
		records = records[:maxSessionCards]
	}
	cards := make([]sessionCard, 0, len(records))
	for _, record := range records {
		if len(record.Requests) == 0 {
			continue
		}
		latest := record.Requests[len(record.Requests)-1]
		requests := make([]sessionRequestCard, 0, len(record.Requests))
		for i := len(record.Requests) - 1; i >= 0; i-- {
			requests = append(requests, makeSessionRequestCard(record.Requests[i]))
		}
		state, class := sessionState(latest.State)
		status := latest.Status
		cards = append(cards, sessionCard{ID: record.ID, ShortID: shortSessionID(record.ID), Started: record.FirstSeen.Format("15:04:05"), Duration: formatSessionDuration(record.FirstSeen, latest.CompletedAt), State: state, StateClass: class, Status: formatStatus(status), StatusClass: statusClass(status), RequestCount: record.RequestCount, Latest: makeSessionRequestCard(latest), Requests: requests})
	}
	return cards
}

func (h *sessionHub) renderCards() (string, error) {
	var output bytes.Buffer
	if err := getTemplate("session-cards.html").Execute(&output, h.cards()); err != nil {
		return "", err
	}
	return output.String(), nil
}

func (h *sessionHub) close() {
	h.mu.Lock()
	for _, record := range h.records {
		for _, request := range record.Requests {
			if request.ResponsePayload != nil {
				_ = request.ResponsePayload.Close()
			}
		}
	}
	payloads := h.payloads
	h.payloads = nil
	statsFile := h.statsFile
	h.statsFile = nil
	h.mu.Unlock()
	if payloads != nil {
		_ = payloads.Close()
	}
	if statsFile != nil {
		_ = statsFile.Close()
	}
}

// syncStatsEntry inserts or refreshes the in-memory stats entry for a request
// so that stats always reflect the latest state, including bytes streamed so
// far. It must be called with h.mu held, except during startup while the hub
// is not yet shared.
func (h *sessionHub) syncStatsEntry(sessionID string, request *sessionRequest) {
	if index, ok := h.statsIndex[request.Sequence]; ok && index < len(h.history) {
		updateStatsEntry(h.history[index], request)
		return
	}
	h.statsIndex[request.Sequence] = len(h.history)
	h.history = append(h.history, makeStatsEntry(sessionID, request))
}

// seedStatsEntry records a restored request into the stats history at
// startup. It must be called with h.mu held (or before the hub is shared).
func (h *sessionHub) seedStatsEntry(sessionID string, request *sessionRequest) {
	h.syncStatsEntry(sessionID, request)
}

func (h *sessionHub) requestKey(tracked *trackedSession) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if request := h.findRequestLocked(tracked); request != nil {
		return request.RequestKey
	}
	return ""
}

func (h *sessionHub) readPayload(sessionID, kind string, tail int64) ([]byte, bool, error) {
	h.mu.Lock()
	record := h.records[sessionID]
	if record == nil || len(record.Requests) == 0 {
		h.mu.Unlock()
		return nil, false, nil
	}
	request := record.Requests[len(record.Requests)-1]
	key := request.RequestKey
	if kind == "response" {
		key = request.ResponseKey
	}
	h.mu.Unlock()
	if key == "" || h.payloads == nil {
		return nil, false, nil
	}
	data, err := h.payloads.Read(key, tail)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, true, err
	}
	return data, true, nil
}

// payloadInfo resolves the payload key for a session and the content type
// recorded for it.
func (h *sessionHub) payloadInfo(sessionID, kind string) (key, contentType string, found bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	record := h.records[sessionID]
	if record == nil || len(record.Requests) == 0 {
		return "", "", false
	}
	request := record.Requests[len(record.Requests)-1]
	if kind == "response" {
		return request.ResponseKey, request.ContentType, request.ResponseKey != ""
	}
	return request.RequestKey, request.RequestContentType, request.RequestKey != ""
}

func (h *sessionHub) subscribe() chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	client := make(chan struct{}, 1)
	h.subscribers[client] = struct{}{}
	return client
}

func (h *sessionHub) unsubscribe(client chan struct{}) {
	h.mu.Lock()
	delete(h.subscribers, client)
	close(client)
	h.mu.Unlock()
}

func (h *sessionHub) publishLocked() {
	for client := range h.subscribers {
		select {
		case client <- struct{}{}:
		default:
		}
	}
}

func (h *sessionHub) findRequestLocked(tracked *trackedSession) *sessionRequest {
	record := h.records[tracked.sessionID]
	if record == nil {
		return nil
	}
	for _, request := range record.Requests {
		if request.Sequence == tracked.sequence {
			return request
		}
	}
	return nil
}

func (p *Proxy) serveSessions(w http.ResponseWriter, r *http.Request) {
	if p.Sessions == nil {
		http.Error(w, "session tracking is unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path == "/sessions" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		content, err := p.Sessions.renderCards()
		if err != nil {
			http.Error(w, "failed to render sessions", http.StatusInternalServerError)
			return
		}
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
		content, err := p.Sessions.renderCards()
		if err != nil || writeSessionSSE(w, content) != nil {
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

func (p *Proxy) serveSessionPayload(w http.ResponseWriter, r *http.Request) {
	if p.Sessions == nil {
		http.Error(w, "session tracking is unavailable", http.StatusServiceUnavailable)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/sessions/"), "/")
	if len(parts) != 2 || (parts[1] != "request" && parts[1] != "response") {
		http.NotFound(w, r)
		return
	}
	// ?full=1 streams the complete on-disk payload instead of the preview
	// tail, so the whole response can be inspected without loading it on every
	// live refresh.
	if r.URL.Query().Get("full") == "1" {
		_, contentType, found := p.Sessions.payloadInfo(parts[0], parts[1])
		if !found {
			http.NotFound(w, r)
			return
		}
		data, found, err := p.Sessions.readPayload(parts[0], parts[1], 0)
		if !found {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "failed to read session payload", http.StatusInternalServerError)
			return
		}
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(data)
		return
	}
	var tail int64
	if parts[1] == "response" {
		tail = 64 << 10
	}
	data, found, err := p.Sessions.readPayload(parts[0], parts[1], tail)
	if !found {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "failed to read session payload", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

func writeSessionSSE(w io.Writer, content string) error {
	return writeNamedSSE(w, "sessions", content)
}

func writeNamedSSE(w io.Writer, event, content string) error {
	if _, err := io.WriteString(w, "event: "+event+"\n"); err != nil {
		return err
	}
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r", ""), "\n") {
		if _, err := io.WriteString(w, "data: "+line+"\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func newSessionID(now time.Time, sequence uint64) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		for i := range value {
			value[i] = byte(sequence >> (uint(i%8) * 8))
		}
	}
	milliseconds := uint64(now.UnixMilli())
	value[0] = byte(milliseconds >> 40)
	value[1] = byte(milliseconds >> 32)
	value[2] = byte(milliseconds >> 24)
	value[3] = byte(milliseconds >> 16)
	value[4] = byte(milliseconds >> 8)
	value[5] = byte(milliseconds)
	value[6] = 0x70 | value[6]&0x0f
	value[8] = 0x80 | value[8]&0x3f
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func redactHeaders(headers http.Header) []sessionHeader {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make([]sessionHeader, 0, len(keys))
	for _, key := range keys {
		value := strings.Join(headers.Values(key), ", ")
		if isSensitiveHeader(key) {
			value = "[redacted]"
		}
		value = strings.ReplaceAll(strings.ReplaceAll(value, "\n", " "), "\r", " ")
		if len(value) > 220 {
			value = value[:217] + "..."
		}
		output = append(output, sessionHeader{Name: key, Value: value})
	}
	return output
}

func isSensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key":
		return true
	default:
		return false
	}
}

func makeSessionRequestCard(request *sessionRequest) sessionRequestCard {
	state, _ := sessionState(request.State)
	events := make([]sessionEventCard, 0, len(request.Events))
	for _, event := range request.Events {
		events = append(events, sessionEventCard{At: event.At.Format("15:04:05"), Kind: event.Kind, Detail: event.Detail})
	}
	model := request.Model
	if request.OriginalModel != "" && request.OriginalModel != request.Model {
		model = request.OriginalModel + " => " + request.Model
	}
	return sessionRequestCard{Method: request.Method, Path: request.Path, Started: request.StartedAt.Format("15:04:05"), Duration: formatSessionDuration(request.StartedAt, request.CompletedAt), State: state, Status: formatStatus(request.Status), Bytes: formatBytes(request.Bytes), Headers: request.Headers, ContentType: request.ContentType, RequestContentType: request.RequestContentType, RequestBytes: formatBytes64(request.RequestBytes), ResponseBytes: formatBytes64(request.ResponseBytes), AppSelector: request.AppSelector, Upstream: request.Upstream, Model: model, HasRequestBody: request.RequestBytes > 0, HasResponseBody: request.ResponseBytes > 0, Events: events}
}

func sessionState(state string) (string, string) {
	switch state {
	case "connecting":
		return "connecting", "is-connecting"
	case "streaming":
		return "streaming", "is-streaming"
	case "client closed":
		return "client closed", "is-warning"
	case "timed out", "interrupted":
		return state, "is-error"
	default:
		return "completed", "is-completed"
	}
}

func formatStatus(status int) string {
	if status == 0 {
		return "pending"
	}
	return fmt.Sprintf("%d", status)
}

func statusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "status-2xx"
	case status >= 300 && status < 400:
		return "status-3xx"
	case status >= 400 && status < 500:
		return "status-4xx"
	case status >= 500:
		return "status-5xx"
	default:
		return "status-pending"
	}
}

func formatSessionDuration(start, end time.Time) string {
	if start.IsZero() {
		return "-"
	}
	if end.IsZero() {
		end = time.Now()
	}
	duration := end.Sub(start)
	if duration < time.Second {
		return duration.Round(time.Millisecond).String()
	}
	if duration < time.Minute {
		return duration.Round(time.Millisecond).String()
	}
	return duration.Round(time.Second).String()
}

func formatBytes(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

func formatBytes64(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

func shortSessionID(id string) string {
	if len(id) <= 18 {
		return id
	}
	return id[:8] + "..." + id[len(id)-6:]
}
