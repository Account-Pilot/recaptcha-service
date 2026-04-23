// Package custom implements the recaptcha.Solver interface against the
// volatileticketing custom solver at https://tmpt.volatileticketing.com/solve.
package custom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Account-Pilot/recaptcha-service"
)

const (
	defaultEndpoint  = "https://tmpt.volatileticketing.com/solve"
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

type Config struct {
	APIKey     string
	SiteKey    string
	UserAgent  string
	Endpoint   string
	Enhanced   bool          // default Enhanced flag for every solve
	HTTPClient *http.Client  // default: 3-minute timeout
	Timeout    time.Duration // shorthand for HTTPClient timeout when HTTPClient is nil
}

type Client struct {
	mu  sync.RWMutex // guards cfg.APIKey and cfg.SiteKey
	cfg Config
	hc  *http.Client
}

var _ recaptcha.Solver = (*Client)(nil)

// SetAPIKey rotates the custom-solver API key used for subsequent requests.
// Safe to call concurrently with Solve/SolveTask.
func (c *Client) SetAPIKey(key string) {
	c.mu.Lock()
	c.cfg.APIKey = key
	c.mu.Unlock()
}

// SetSiteKey rotates the default sitekey used when a Task doesn't set its own.
// Safe to call concurrently with Solve/SolveTask.
func (c *Client) SetSiteKey(key string) {
	c.mu.Lock()
	c.cfg.SiteKey = key
	c.mu.Unlock()
}

// APIKey returns the current API key.
func (c *Client) APIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.APIKey
}

// SiteKey returns the current default sitekey.
func (c *Client) SiteKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.SiteKey
}

func (c *Client) keys() (apiKey, siteKey string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.APIKey, c.cfg.SiteKey
}

func New(apiKey, siteKey string) *Client {
	return NewWithConfig(Config{APIKey: apiKey, SiteKey: siteKey})
}

func NewWithConfig(cfg Config) *Client {
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	if cfg.HTTPClient == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 3 * time.Minute
		}
		cfg.HTTPClient = &http.Client{Timeout: timeout}
	}
	return &Client{cfg: cfg, hc: cfg.HTTPClient}
}

func (c *Client) Solve(ctx context.Context, url string, t recaptcha.Type, action string) (string, error) {
	return c.SolveTask(ctx, recaptcha.Task{URL: url, Type: t, Action: action})
}

func (c *Client) SolveTask(ctx context.Context, task recaptcha.Task) (string, error) {
	apiKey, siteKey := c.keys()
	c.applyDefaults(&task, siteKey)
	if err := validate(apiKey, task); err != nil {
		return "", err
	}

	body, _ := json.Marshal(request{
		Task:      string(task.Type),
		UserAgent: task.UserAgent,
		URL:       task.URL,
		SiteKey:   task.SiteKey,
		Action:    task.Action,
		Enhanced:  task.Enhanced,
		Cookies:   task.Cookies,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	res, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("custom: http %d: %s", res.StatusCode, string(raw))
	}

	var parsed response
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("custom: parse response: %w", err)
	}
	if !parsed.Success {
		if parsed.Error != "" {
			return "", fmt.Errorf("custom: %s", parsed.Error)
		}
		return "", fmt.Errorf("custom: solve failed: %s", string(raw))
	}
	return parsed.Token, nil
}

func (c *Client) applyDefaults(t *recaptcha.Task, siteKey string) {
	if t.SiteKey == "" {
		t.SiteKey = siteKey
	}
	if t.UserAgent == "" {
		t.UserAgent = c.cfg.UserAgent
	}
	if !t.Enhanced {
		t.Enhanced = c.cfg.Enhanced
	}
}

func validate(apiKey string, t recaptcha.Task) error {
	if apiKey == "" {
		return recaptcha.ErrMissingAPIKey
	}
	if t.URL == "" {
		return recaptcha.ErrMissingURL
	}
	if t.Type == "" {
		return recaptcha.ErrMissingType
	}
	if t.SiteKey == "" {
		return recaptcha.ErrMissingSiteKey
	}
	return nil
}

type request struct {
	Task      string   `json:"task"`
	UserAgent string   `json:"userAgent"`
	URL       string   `json:"url"`
	SiteKey   string   `json:"sitekey"`
	Action    string   `json:"action"`
	Enhanced  bool     `json:"enhanced"`
	Cookies   []string `json:"cookies,omitempty"`
}

type response struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
	Error   string `json:"error"`
}
