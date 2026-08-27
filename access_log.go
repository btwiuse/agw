package agw

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"runtime/debug"
)

type accessWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	// err records the first failed client write. A write failure is the only
	// reliable signal that the client hung up: reading r.Context().Err() after
	// the handler returns races with the client closing the connection right
	// after receiving a complete response (curl does exactly that), which
	// misclassifies delivered requests as "client closed".
	err           error
	onWriteHeader func(int)
}

func (w *accessWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	if w.onWriteHeader != nil {
		w.onWriteHeader(status)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += n
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

func (w *accessWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func requestLogger(logger Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy, _ := next.(*Proxy)
		var session *trackedSession
		if proxy != nil && proxy.Sessions != nil && shouldTrackSession(r) {
			session = proxy.Sessions.start(r)
			r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, session))
		}
		if loggerProxyDebug(next) {
			logger.Info("request headers", "headers", headerMap(r.Header))
		}
		writer := &accessWriter{ResponseWriter: w}
		if session != nil {
			writer.onWriteHeader = session.connected
		}
		next.ServeHTTP(writer, r)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		if session != nil {
			// Classify the terminal state from the client write outcome, not
			// from a context read after the handler returned. By the time the
			// handler is back, the client may already have closed the
			// connection after a fully delivered response, which would turn a
			// successful request into a spurious "client closed". A failed
			// write proves the hangup happened during the response, and the
			// context error read then is stable (cancellation is monotonic).
			var ctxErr error
			if writer.err != nil {
				ctxErr = r.Context().Err()
				if ctxErr == nil {
					ctxErr = writer.err
				}
			}
			session.complete(status, writer.bytes, ctxErr)
		}
	})
}

// wroteHeaderWriter tracks whether a response has started so a recovered panic
// knows whether it can still write a 500, while preserving Flusher support for
// SSE endpoints.
type wroteHeaderWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *wroteHeaderWriter) WriteHeader(status int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *wroteHeaderWriter) Write(data []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(data)
}

func (w *wroteHeaderWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// recoverJSON turns any uncaught panic into a structured JSON log line instead
// of letting the runtime print a raw stack trace to stderr.
func recoverJSON(logger Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker := &wroteHeaderWriter{ResponseWriter: w}
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("panic recovered",
					"error", fmt.Sprint(recovered),
					"method", r.Method,
					"path", r.URL.RequestURI(),
					"stack", string(debug.Stack()))
				if !tracker.wrote {
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}
		}()
		next.ServeHTTP(tracker, r)
	})
}

// requiresManagementAuth reports whether a request hits the admin surface
// (config page, config API, logs, session journal). CORS preflight requests
// stay open because browsers never attach credentials to them.
func requiresManagementAuth(r *http.Request) bool {
	if r.Method == http.MethodOptions {
		return false
	}
	return isManagementRequest(r)
}

// basicAuth guards the management endpoints with HTTP Basic auth. It is
// intentionally only applied to the admin surface; proxied API traffic passes
// through untouched.
func basicAuth(logger Logger, username, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresManagementAuth(r) {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userOK := ok && subtle.ConstantTimeCompare([]byte(user), []byte(username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1
		if !userOK || !passOK {
			logger.Warn("management auth failed", "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Basic realm="agw"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func shouldTrackSession(r *http.Request) bool {
	// Track every proxied request. Session-Id/Thread-Id are Codex-specific
	// headers and path prefixes vary by client (/v1/, /anthropic/v1/, ...),
	// so neither is a reliable signal. Management endpoints are the only
	// requests that bypass the proxy, and isManagementRequest covers all of
	// them, so "not management" is exactly "goes through the proxy".
	return !isManagementRequest(r)
}

func loggerProxyDebug(next http.Handler) bool {
	proxy, ok := next.(*Proxy)
	if !ok {
		return false
	}
	proxy.Mu.RLock()
	debug := proxy.Debug
	proxy.Mu.RUnlock()
	return debug
}

// headerMap converts http.Header into a plain map for structured logging:
// single-valued headers become strings, multi-valued headers stay arrays.
func headerMap(headers http.Header) map[string]any {
	structured := make(map[string]any, len(headers))
	for key, values := range headers {
		if len(values) == 1 {
			structured[key] = values[0]
		} else {
			structured[key] = values
		}
	}
	return structured
}

type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}
