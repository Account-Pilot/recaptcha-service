# recaptcha-service

A unified Go SDK for solving Google reCAPTCHA through multiple providers. Pick
your provider by import — the API surface is identical across all three.

| Provider     | Subpackage                                                         | API key |
| ------------ | ------------------------------------------------------------------ | ------- |
| AntiCaptcha  | `github.com/Account-Pilot/recaptcha-service/anticaptcha`           | [anti-captcha.com](https://anti-captcha.com) |
| CapSolver    | `github.com/Account-Pilot/recaptcha-service/capsolver`             | [capsolver.com](https://capsolver.com) |
| Custom       | `github.com/Account-Pilot/recaptcha-service/custom`                | volatileticketing |

Zero external dependencies — just stdlib.

## Install

```sh
go get github.com/Account-Pilot/recaptcha-service
```

## Usage

Configure the client once with the API key and sitekey, then call `Solve`
with just the per-request fields (URL, type, action):

```go
import (
    "context"

    "github.com/Account-Pilot/recaptcha-service"
    "github.com/Account-Pilot/recaptcha-service/custom"
)

c := custom.New("API_KEY", "6Lxxx...")
token, err := c.Solve(ctx, "https://example.com/login", recaptcha.V3Enterprise, "login")
```

Swap `custom` for `anticaptcha` or `capsolver` — the call stays the same:

```go
import "github.com/Account-Pilot/recaptcha-service/anticaptcha"

c := anticaptcha.New("API_KEY", "6Lxxx...")
token, err := c.Solve(ctx, url, recaptcha.V3Enterprise, "login")
```

### Per-request overrides

Use `SolveTask` when a single request needs a different sitekey, proxy, min
score, etc:

```go
token, err := c.SolveTask(ctx, recaptcha.Task{
    URL:      "https://example.com/login",
    Type:     recaptcha.V3Enterprise,
    Action:   "login",
    SiteKey:  "6Ldifferent...",
    MinScore: 0.9,
})
```

### Swapping providers at runtime

All three clients implement `recaptcha.Solver`, so they're interchangeable:

```go
var solver recaptcha.Solver
if useCapsolver {
    solver = capsolver.New(apiKey, siteKey)
} else {
    solver = anticaptcha.New(apiKey, siteKey)
}
token, err := solver.Solve(ctx, url, recaptcha.V3Enterprise, "login")
```

## Captcha types

```go
recaptcha.V3                   // ReCaptchaV3TaskProxyLess
recaptcha.V3Proxied            // ReCaptchaV3Task
recaptcha.V3Enterprise         // ReCaptchaV3EnterpriseTaskProxyLess
recaptcha.V3EnterpriseProxied  // ReCaptchaV3EnterpriseTask
recaptcha.V2                   // ReCaptchaV2TaskProxyLess
recaptcha.V2Proxied            // ReCaptchaV2Task
recaptcha.V2Enterprise         // ReCaptchaV2EnterpriseTaskProxyLess
recaptcha.V2EnterpriseProxied  // ReCaptchaV2EnterpriseTask
```

The `Proxied` variants require a `Proxy` field on `Task`; the ProxyLess
variants don't. `IsV3`, `IsEnterprise`, and `IsProxied` helpers are exposed
for runtime checks.

## Client configuration

Each subpackage exposes a `Config` struct and `NewWithConfig` for full
control (HTTP client, polling interval, max wait, default user agent, ...):

```go
c := anticaptcha.NewWithConfig(anticaptcha.Config{
    APIKey:    apiKey,
    SiteKey:   siteKey,
    MinScore:  0.9,
    PollEvery: 3 * time.Second,
    MaxWait:   90 * time.Second,
})
```

### Custom solver

The custom solver sends a synchronous request to
`tmpt.volatileticketing.com/solve` — no polling:

```go
c := custom.NewWithConfig(custom.Config{
    APIKey:    "f4fe08d7...",
    SiteKey:   "6Lxxx...",
    UserAgent: "Mozilla/5.0 ...",
    Enhanced:  true, // optional default
})
```

## Errors

Common sentinel errors returned by every provider:

```go
recaptcha.ErrMissingAPIKey
recaptcha.ErrMissingSiteKey
recaptcha.ErrMissingURL
recaptcha.ErrMissingType
recaptcha.ErrTimeout
```

Provider-specific errors (bad API key, insufficient balance, etc) are
wrapped with the provider name as prefix, e.g. `anticaptcha: ERROR_KEY_DOES_NOT_EXIST: ...`.

## Example

A runnable example is in `examples/main.go` — it reads API keys from
`ANTICAPTCHA_KEY`, `CAPSOLVER_KEY`, and `VOLATILE_KEY` env vars and runs
whichever providers have keys set:

```sh
ANTICAPTCHA_KEY=... CAPSOLVER_KEY=... go run ./examples
```
