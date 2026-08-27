package agw

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Options configures the gateway when started programmatically or through the
// CLI.
type Options struct {
	ConfigPath string
	Listen     string
	Timeout    time.Duration
	// AllowDebug gates the config's debug flag: without it, debug header
	// logging stays off no matter what the config file or the client says.
	AllowDebug bool
	LogStderr  bool
	// AdminUser and AdminPassword enable HTTP Basic Auth on the management
	// surface. They fall back to the AGW_ADMIN_USER / AGW_ADMIN_PASSWORD
	// environment variables and must always be set together.
	AdminUser     string
	AdminPassword string
	// Dev enables developer conveniences: templates are loaded from the
	// templates/ directory on disk with mtime-based hot reload instead of the
	// embedded copy.
	Dev bool
	// DataDir persists all runtime data — session metadata (JSON), intercepted
	// payloads and the request log — under this directory, so the journal and
	// log feed survive restarts. Empty keeps sessions in memory and payloads
	// in a temporary directory.
	DataDir string
}

// DefaultListenAddress derives the listen address from PORT, falling back to
// :8080. When PORT is set but not numeric, the offending value is returned so
// the caller can warn about it.
func DefaultListenAddress() (addr, invalidPort string) {
	addr = ":8080"
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		if _, err := strconv.Atoi(port); err == nil {
			return ":" + port, ""
		}
		return addr, port
	}
	return addr, ""
}

// RunWithOptions starts the gateway and blocks until the HTTP server exits.
func RunWithOptions(opts Options) error {
	devTemplates.Store(opts.Dev)
	if opts.Timeout < 0 {
		return errors.New("timeout must be zero or greater")
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = "config.yaml"
	}
	if opts.Listen == "" {
		opts.Listen = ":8080"
	}
	adminUser, adminPassword, err := managementCredentials(opts)
	if err != nil {
		return err
	}

	created, err := ensureConfig(opts.ConfigPath)
	if err != nil {
		return err
	}
	settings, err := loadSettings(FileConfig(opts.ConfigPath))
	if err != nil {
		return err
	}
	// Secrets are injected by the admin browser via POST /config/secrets and
	// only ever live in memory. At startup, legacy literal values in
	// config.yaml are externalized in memory and the file is rewritten to
	// secret:<key> references so plaintext never stays on disk.
	upstreams, secretValues, migrated, err := externalizeSecrets(settings.Upstreams, map[string]string{})
	if err != nil {
		return err
	}
	var hub *logHub
	if opts.DataDir != "" {
		hub = newLogHubPersistent(opts.DataDir)
	} else {
		hub = newLogHub()
	}
	defer hub.close()
	var sessions *sessionHub
	if opts.DataDir != "" {
		sessions = newSessionHubPersistent(opts.DataDir)
	} else {
		sessions = newSessionHub()
	}
	defer sessions.close()
	logSink := io.Writer(hub)
	if opts.LogStderr {
		logSink = io.MultiWriter(os.Stderr, hub)
	}
	logger := slog.New(slog.NewJSONHandler(logSink, nil))
	client := newHTTPClient(opts.Timeout, nil)
	if migrated {
		settings.Upstreams = upstreams
		encoded, marshalErr := yaml.Marshal(settings)
		if marshalErr != nil {
			return marshalErr
		}
		if writeErr := FileConfig(opts.ConfigPath).Write(encoded, 0600); writeErr != nil {
			logger.Error("failed to rewrite config with secret references", "path", opts.ConfigPath, "error", writeErr.Error())
		} else {
			logger.Info("externalized auth values into memory; open the management UI to keep them in the browser", "config", opts.ConfigPath)
		}
	}
	proxy := &Proxy{Upstreams: upstreams, AppSelectors: settings.AppSelectors, Pricing: settings.Pricing, Client: client, Logger: logger, Config: FileConfig(opts.ConfigPath), LogHub: hub, Sessions: sessions, AllowDebug: opts.AllowDebug, Debug: settings.Debug && opts.AllowDebug, SecretValues: secretValues}
	if sessions != nil {
		sessions.setPricing(settings.Pricing)
	}

	if adminUser != "" {
		logger.Info("management auth enabled", "username", adminUser)
	}
	server := &http.Server{
		Addr:              opts.Listen,
		Handler:           gatewayHandler(logger, proxy, adminUser, adminPassword),
		ErrorLog:          slog.NewLogLogger(slog.NewJSONHandler(logSink, nil), slog.LevelError),
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("server listening", "addr", opts.Listen, "upstreams", len(settings.Upstreams), "debug", proxy.Debug)
	if created {
		logger.Info("config file created with a starter template", "path", opts.ConfigPath)
	}
	if opts.Dev {
		logger.Info("dev mode: templates loaded from disk with hot reload", "dir", "templates")
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

const defaultConfigTemplate = `# AGW gateway config — created automatically because the file was missing.
# Manage upstreams and app selectors in the management UI; saving rewrites this file.
debug: false
appSelectors: []
upstreams:
  - name: default
    url: https://example.com/v1
    authorization:
      type: none
`

// ensureConfig creates the config file with a starter template when it is
// missing, so the gateway can boot and be configured from the UI. It reports
// whether a new file was written.
func ensureConfig(path string) (bool, error) {
	if _, err := os.ReadFile(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return false, err
		}
	}
	if err := os.WriteFile(path, []byte(defaultConfigTemplate), 0600); err != nil {
		return false, err
	}
	return true, nil
}

// gatewayHandler builds the complete HTTP middleware chain (request logging,
// management Basic Auth, panic recovery) around the proxy. It does not depend
// on a net.Listener, so the same handler can be served by net/http on a real
// socket or by a custom transport such as a js/wasm bridge.
func gatewayHandler(logger Logger, proxy *Proxy, adminUser, adminPassword string) http.Handler {
	handler := requestLogger(logger, proxy)
	if adminUser != "" {
		handler = basicAuth(logger, adminUser, adminPassword, handler)
	}
	return recoverJSON(logger, handler)
}

// Run parses command-line arguments and starts the gateway. It exists for
// compatibility; the cobra CLI in cmd/agw uses RunWithOptions directly.
func Run(args []string) error {
	defaultAddr, invalidPort := DefaultListenAddress()
	opts := Options{ConfigPath: "config.yaml", Listen: defaultAddr}
	flags := flag.NewFlagSet("agw", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "path to upstream config")
	flags.StringVar(&opts.Listen, "listen", defaultAddr, "listen address")
	flags.DurationVar(&opts.Timeout, "timeout", 0, "per-upstream request timeout; 0 disables it")
	flags.BoolVar(&opts.AllowDebug, "allow-debug", false, "honor debug: true from the client config and log request headers; without it debug stays off")
	flags.BoolVar(&opts.LogStderr, "log-stderr", false, "also write logs to stderr")
	flags.BoolVar(&opts.Dev, "dev", false, "dev mode: load templates from disk with hot reload")
	flags.StringVar(&opts.DataDir, "data-dir", "", "persist sessions, payloads and logs to this directory")
	flags.StringVar(&opts.AdminUser, "admin-user", "", "Basic Auth username for the management UI (env: AGW_ADMIN_USER; must be paired with --admin-password)")
	flags.StringVar(&opts.AdminPassword, "admin-password", "", "Basic Auth password for the management UI (env: AGW_ADMIN_PASSWORD)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stdout)
			flags.Usage()
			return nil
		}
		return err
	}
	if invalidPort != "" {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("server config error", "port", invalidPort, "fallback", defaultAddr)
	}
	return RunWithOptions(opts)
}

// managementCredentials resolves the management Basic Auth pair from the
// options first, falling back to the AGW_ADMIN_USER / AGW_ADMIN_PASSWORD
// environment variables. Both must be set together.
func managementCredentials(opts Options) (user, password string, err error) {
	user = opts.AdminUser
	if user == "" {
		user = os.Getenv("AGW_ADMIN_USER")
	}
	password = opts.AdminPassword
	if password == "" {
		password = os.Getenv("AGW_ADMIN_PASSWORD")
	}
	if (user == "") != (password == "") {
		return "", "", errors.New("AGW_ADMIN_USER and AGW_ADMIN_PASSWORD must be set together")
	}
	return user, password, nil
}

func newHTTPClient(timeout time.Duration, transport http.RoundTripper) *http.Client {
	client := &http.Client{}
	if timeout > 0 {
		client.Timeout = timeout
	}
	if transport != nil {
		client.Transport = transport
	}
	return client
}
