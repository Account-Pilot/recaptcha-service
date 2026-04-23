// Package recaptcha provides a unified SDK for solving Google reCAPTCHA
// through multiple providers: AntiCaptcha, CapSolver, and a custom solver.
//
// Construct a provider client from one of the sub-packages, then call Solve
// with only the per-request fields (URL, type, action):
//
//	c := custom.New("API_KEY", "6Lxxx")
//	token, err := c.Solve(ctx, "https://example.com/login", recaptcha.V3Enterprise, "login")
package recaptcha

import (
	"context"
	"errors"
)

// Type names a reCAPTCHA task variant. Values follow the AntiCaptcha /
// CapSolver naming so they can be passed directly to both APIs.
type Type string

const (
	V3                  Type = "ReCaptchaV3TaskProxyLess"
	V3Proxied           Type = "ReCaptchaV3Task"
	V3Enterprise        Type = "ReCaptchaV3EnterpriseTaskProxyLess"
	V3EnterpriseProxied Type = "ReCaptchaV3EnterpriseTask"
	V2                  Type = "ReCaptchaV2TaskProxyLess"
	V2Proxied           Type = "ReCaptchaV2Task"
	V2Enterprise        Type = "ReCaptchaV2EnterpriseTaskProxyLess"
	V2EnterpriseProxied Type = "ReCaptchaV2EnterpriseTask"
)

// Task is the full per-request payload accepted by provider.SolveTask.
// Most callers should use Solver.Solve instead and configure defaults
// (API key, sitekey, user agent, ...) once on the client.
type Task struct {
	URL     string // page URL where the captcha is rendered
	Type    Type   // which reCAPTCHA variant to run
	Action  string // V3 action name (e.g. "login"); ignored by V2
	SiteKey string // Google sitekey (6Lxxx); overrides client default when set

	MinScore  float64 // V3 only; 0 falls back to client default (0.7)
	UserAgent string  // overrides client default when set
	Invisible bool    // V2 invisible widget
	Proxy     string  // http://user:pass@host:port; only for *Proxied types

	// Custom-solver-only fields; ignored by other providers.
	Enhanced bool
	Cookies  []string
}

// Solver produces a reCAPTCHA token. The two methods are equivalent except
// that SolveTask lets callers override per-request fields.
type Solver interface {
	Solve(ctx context.Context, url string, t Type, action string) (string, error)
	SolveTask(ctx context.Context, task Task) (string, error)
}

var (
	ErrMissingAPIKey  = errors.New("recaptcha: api key is required")
	ErrMissingSiteKey = errors.New("recaptcha: sitekey is required")
	ErrMissingURL     = errors.New("recaptcha: url is required")
	ErrMissingType    = errors.New("recaptcha: captcha type is required")
	ErrTimeout        = errors.New("recaptcha: timed out waiting for solve")
)

// IsV3 reports whether t is any V3 variant.
func IsV3(t Type) bool {
	switch t {
	case V3, V3Proxied, V3Enterprise, V3EnterpriseProxied:
		return true
	}
	return false
}

// IsEnterprise reports whether t is any Enterprise variant.
func IsEnterprise(t Type) bool {
	switch t {
	case V3Enterprise, V3EnterpriseProxied, V2Enterprise, V2EnterpriseProxied:
		return true
	}
	return false
}

// IsProxied reports whether t requires proxy fields to be supplied.
func IsProxied(t Type) bool {
	switch t {
	case V3Proxied, V3EnterpriseProxied, V2Proxied, V2EnterpriseProxied:
		return true
	}
	return false
}
