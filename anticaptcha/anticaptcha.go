// Package anticaptcha implements the recaptcha.Solver interface against
// the AntiCaptcha service (https://anti-captcha.com).
package anticaptcha

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

const baseURL = "https://api.anti-captcha.com"

// Config collects every knob exposed by the AntiCaptcha client.
// APIKey and SiteKey are the only required fields.
type Config struct {
	APIKey     string
	SiteKey    string
	UserAgent  string
	MinScore   float64       // V3 default; zero means 0.7
	HTTPClient *http.Client  // optional; default 30s timeout
	PollEvery  time.Duration // default 5s
	MaxWait    time.Duration // default 2m
}

type Client struct {
	mu  sync.RWMutex // guards cfg.APIKey and cfg.SiteKey — the only fields mutable after construction
	cfg Config
	hc  *http.Client
}

var _ recaptcha.Solver = (*Client)(nil)

// SetAPIKey rotates the AntiCaptcha API key used for subsequent requests.
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

// New builds a Client with the minimum required settings.
func New(apiKey, siteKey string) *Client {
	return NewWithConfig(Config{APIKey: apiKey, SiteKey: siteKey})
}

// NewWithConfig builds a Client from an explicit Config, filling zero-valued
// fields with sensible defaults.
func NewWithConfig(cfg Config) *Client {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 5 * time.Second
	}
	if cfg.MaxWait == 0 {
		cfg.MaxWait = 2 * time.Minute
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = 0.7
	}
	return &Client{cfg: cfg, hc: cfg.HTTPClient}
}

// Solve resolves the captcha using the client's configured sitekey.
func (c *Client) Solve(ctx context.Context, url string, t recaptcha.Type, action string) (string, error) {
	return c.SolveTask(ctx, recaptcha.Task{URL: url, Type: t, Action: action})
}

// SolveTask runs an arbitrary Task. Missing fields fall back to the client
// configuration.
func (c *Client) SolveTask(ctx context.Context, task recaptcha.Task) (string, error) {
	apiKey, siteKey := c.keys()
	c.applyDefaults(&task, siteKey)
	if err := validate(apiKey, task); err != nil {
		return "", err
	}

	id, err := c.createTask(ctx, apiKey, task)
	if err != nil {
		return "", err
	}
	return c.pollResult(ctx, apiKey, id)
}

// keys takes a single read-lock snapshot of the mutable API/site keys so the
// rest of a single Solve call sees a consistent pair even if another
// goroutine rotates them mid-flight.
func (c *Client) keys() (apiKey, siteKey string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.APIKey, c.cfg.SiteKey
}

func (c *Client) applyDefaults(t *recaptcha.Task, siteKey string) {
	if t.SiteKey == "" {
		t.SiteKey = siteKey
	}
	if t.UserAgent == "" {
		t.UserAgent = c.cfg.UserAgent
	}
	if t.MinScore == 0 {
		t.MinScore = c.cfg.MinScore
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

type createBody struct {
	ClientKey string         `json:"clientKey"`
	Task      map[string]any `json:"task"`
}

type createResp struct {
	ErrorID          int    `json:"errorId"`
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
	TaskID           int64  `json:"taskId"`
}

// taskTypeFor translates the library's canonical Type to AntiCaptcha's task
// type string. AntiCaptcha differs from CapSolver in two ways:
//   - spelling: "Recaptcha" (single capital) and "Proxyless" (lowercase L)
//   - V3 Enterprise: expressed as the regular V3 task + isEnterprise:true,
//     not as a dedicated task type
//
// The second return value is whether isEnterprise:true must be appended to
// the task body (true only for V3 Enterprise variants).
func taskTypeFor(t recaptcha.Type) (string, bool) {
	switch t {
	case recaptcha.V3:
		return "RecaptchaV3TaskProxyless", false
	case recaptcha.V3Proxied:
		return "RecaptchaV3Task", false
	case recaptcha.V3Enterprise:
		return "RecaptchaV3TaskProxyless", true
	case recaptcha.V3EnterpriseProxied:
		return "RecaptchaV3Task", true
	case recaptcha.V2:
		return "RecaptchaV2TaskProxyless", false
	case recaptcha.V2Proxied:
		return "RecaptchaV2Task", false
	case recaptcha.V2Enterprise:
		return "RecaptchaV2EnterpriseTaskProxyless", false
	case recaptcha.V2EnterpriseProxied:
		return "RecaptchaV2EnterpriseTask", false
	}
	// Fall back to the raw string; lets callers experiment with task types
	// we haven't hard-coded yet.
	return string(t), false
}

func (c *Client) createTask(ctx context.Context, apiKey string, t recaptcha.Task) (int64, error) {
	taskType, enterprise := taskTypeFor(t.Type)
	task := map[string]any{
		"type":       taskType,
		"websiteURL": t.URL,
		"websiteKey": t.SiteKey,
	}

	if recaptcha.IsV3(t.Type) {
		task["pageAction"] = t.Action
		task["minScore"] = t.MinScore
		if enterprise {
			task["isEnterprise"] = true
		}
	} else {
		if t.Invisible {
			task["isInvisible"] = true
		}
		if t.UserAgent != "" {
			task["userAgent"] = t.UserAgent
		}
		if recaptcha.IsEnterprise(t.Type) && t.Action != "" {
			task["enterprisePayload"] = map[string]string{"s": t.Action}
		}
	}

	body, _ := json.Marshal(createBody{ClientKey: apiKey, Task: task})

	var resp createResp
	if err := c.do(ctx, "/createTask", body, &resp); err != nil {
		return 0, err
	}
	if resp.ErrorID != 0 {
		return 0, fmt.Errorf("anticaptcha: %s: %s", resp.ErrorCode, resp.ErrorDescription)
	}
	return resp.TaskID, nil
}

type resultResp struct {
	ErrorID          int    `json:"errorId"`
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
	Status           string `json:"status"`
	Solution         struct {
		GRecaptchaResponse string `json:"gRecaptchaResponse"`
	} `json:"solution"`
}

func (c *Client) pollResult(ctx context.Context, apiKey string, taskID int64) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"clientKey": apiKey,
		"taskId":    taskID,
	})

	deadline := time.Now().Add(c.cfg.MaxWait)
	ticker := time.NewTicker(c.cfg.PollEvery)
	defer ticker.Stop()

	for {
		var res resultResp
		if err := c.do(ctx, "/getTaskResult", body, &res); err != nil {
			return "", err
		}
		if res.ErrorID != 0 {
			return "", fmt.Errorf("anticaptcha: %s: %s", res.ErrorCode, res.ErrorDescription)
		}
		if res.Status == "ready" {
			return res.Solution.GRecaptchaResponse, nil
		}
		if time.Now().After(deadline) {
			return "", recaptcha.ErrTimeout
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Client) do(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("anticaptcha: http %d: %s", res.StatusCode, string(raw))
	}
	return json.Unmarshal(raw, out)
}
