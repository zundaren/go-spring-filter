package cors

import (
	"github.com/go-spring/spring-core/web"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// reference https://github.com/rs/cors/blob/master/cors.go

type Options struct {
	AllowedOrigins         []string
	AllowOriginFunc        func(origin string) bool
	AllowOriginRequestFunc func(r *http.Request, origin string) bool
	AllowedMethods         []string
	AllowedHeaders         []string
	ExposedHeaders         []string
	MaxAge                 int
	AllowCredentials       bool
	AllowPrivateNetwork    bool
	OptionsPassthrough     bool
	OptionsSuccessStatus   int
	Debug                  bool
}

type Logger interface {
	Printf(string, ...interface{})
}

type Cors struct {
	Log                    Logger
	allowedOrigins         []string
	allowedWOrigins        []wildcard
	allowOriginFunc        func(origin string) bool
	allowOriginRequestFunc func(r *http.Request, origin string) bool
	allowedHeaders         []string
	allowedMethods         []string
	exposedHeaders         []string
	maxAge                 int
	allowedOriginsAll      bool
	allowedHeadersAll      bool
	optionsSuccessStatus   int
	allowCredentials       bool
	allowPrivateNetwork    bool
	optionPassthrough      bool
}

// cors must be handled before routing
func PreFilter(options Options) *web.Prefilter {
	return web.NewPrefilter(filter(options))
}

func DefaultPreFilter() *web.Prefilter {
	return web.NewPrefilter(filter(allowAllConfig()))
}

func filter(options Options) web.Filter {
	c := New(options)

	return web.FuncFilter(func(ctx web.Context, chain web.FilterChain) {
		r := ctx.Request()
		w := ctx.ResponseWriter()

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			c.logf("ServeHTTP: Preflight request")
			c.handlePreflight(w, r)
			if c.optionPassthrough {
				chain.Next(ctx)
			} else {
				w.WriteHeader(c.optionsSuccessStatus)
			}
		} else {
			c.logf("ServeHTTP: Actual request")
			c.handleActualRequest(w, r)
			chain.Next(ctx)
		}
	})
}

func New(options Options) *Cors {
	c := &Cors{
		exposedHeaders:         convert(options.ExposedHeaders, http.CanonicalHeaderKey),
		allowOriginFunc:        options.AllowOriginFunc,
		allowOriginRequestFunc: options.AllowOriginRequestFunc,
		allowCredentials:       options.AllowCredentials,
		allowPrivateNetwork:    options.AllowPrivateNetwork,
		maxAge:                 options.MaxAge,
		optionPassthrough:      options.OptionsPassthrough,
	}
	if options.Debug && c.Log == nil {
		c.Log = log.New(os.Stdout, "[cors] ", log.LstdFlags)
	}

	// Allowed Origins
	if len(options.AllowedOrigins) == 0 {
		if options.AllowOriginFunc == nil && options.AllowOriginRequestFunc == nil {
			c.allowedOriginsAll = true
		}
	} else {
		c.allowedOrigins = []string{}
		c.allowedWOrigins = []wildcard{}
		for _, origin := range options.AllowedOrigins {
			// Normalize
			origin = strings.ToLower(origin)
			if origin == "*" {
				c.allowedOriginsAll = true
				c.allowedOrigins = nil
				c.allowedWOrigins = nil
				break
			} else if i := strings.IndexByte(origin, '*'); i >= 0 {
				w := wildcard{origin[0:i], origin[i+1:]}
				c.allowedWOrigins = append(c.allowedWOrigins, w)
			} else {
				c.allowedOrigins = append(c.allowedOrigins, origin)
			}
		}
	}

	// Allowed Headers
	if len(options.AllowedHeaders) == 0 {
		// Use sensible defaults
		c.allowedHeaders = []string{"Origin", "Accept", "Content-Type", "X-Requested-With"}
	} else {
		// Origin is always appended as some browsers will always request for this header at preflight
		c.allowedHeaders = convert(append(options.AllowedHeaders, "Origin"), http.CanonicalHeaderKey)
		for _, h := range options.AllowedHeaders {
			if h == "*" {
				c.allowedHeadersAll = true
				c.allowedHeaders = nil
				break
			}
		}
	}

	// Allowed Methods
	if len(options.AllowedMethods) == 0 {
		// Default is spec's "simple" methods
		c.allowedMethods = []string{http.MethodGet, http.MethodPost, http.MethodHead}
	} else {
		c.allowedMethods = convert(options.AllowedMethods, strings.ToUpper)
	}

	// Options Success Status Code
	if options.OptionsSuccessStatus == 0 {
		c.optionsSuccessStatus = http.StatusNoContent
	} else {
		c.optionsSuccessStatus = options.OptionsSuccessStatus
	}

	return c
}

func allowAllConfig() Options {
	return Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
	}
}

func (c *Cors) handlePreflight(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	origin := r.Header.Get("Origin")

	if r.Method != http.MethodOptions {
		c.logf("  Preflight aborted: %s!=OPTIONS", r.Method)
		return
	}

	headers.Add("Vary", "Origin")
	headers.Add("Vary", "Access-Control-Request-Method")
	headers.Add("Vary", "Access-Control-Request-Headers")

	if origin == "" {
		c.logf("  Preflight aborted: empty origin")
		return
	}
	if !c.isOriginAllowed(r, origin) {
		c.logf("  Preflight aborted: origin '%s' not allowed", origin)
		return
	}

	reqMethod := r.Header.Get("Access-Control-Request-Method")
	if !c.isMethodAllowed(reqMethod) {
		c.logf("  Preflight aborted: method '%s' not allowed", reqMethod)
		return
	}
	reqHeaders := parseHeaderList(r.Header.Get("Access-Control-Request-Headers"))
	if !c.areHeadersAllowed(reqHeaders) {
		c.logf("  Preflight aborted: headers '%v' not allowed", reqHeaders)
		return
	}
	if c.allowedOriginsAll {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.Set("Access-Control-Allow-Origin", origin)
	}
	// Spec says: Since the list of methods can be unbounded, simply returning the method indicated
	// by Access-Control-Request-Method (if supported) can be enough
	headers.Set("Access-Control-Allow-Methods", strings.ToUpper(reqMethod))
	if len(reqHeaders) > 0 {

		// Spec says: Since the list of headers can be unbounded, simply returning supported headers
		// from Access-Control-Request-Headers can be enough
		headers.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", "))
	}
	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}
	if c.allowPrivateNetwork && r.Header.Get("Access-Control-Request-Private-Network") == "true" {
		headers.Set("Access-Control-Allow-Private-Network", "true")
	}
	if c.maxAge > 0 {
		headers.Set("Access-Control-Max-Age", strconv.Itoa(c.maxAge))
	}
	c.logf("  Preflight response headers: %v", headers)
}

func (c *Cors) handleActualRequest(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	origin := r.Header.Get("Origin")

	headers.Add("Vary", "Origin")
	if origin == "" {
		c.logf("  Actual request no headers added: missing origin")
		return
	}
	if !c.isOriginAllowed(r, origin) {
		c.logf("  Actual request no headers added: origin '%s' not allowed", origin)
		return
	}

	// Note that spec does define a way to specifically disallow a simple method like GET or
	// POST. Access-Control-Allow-Methods is only used for pre-flight requests and the
	// spec doesn't instruct to check the allowed methods for simple cross-origin requests.
	// We think it's a nice feature to be able to have control on those methods though.
	if !c.isMethodAllowed(r.Method) {
		c.logf("  Actual request no headers added: method '%s' not allowed", r.Method)

		return
	}
	if c.allowedOriginsAll {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.Set("Access-Control-Allow-Origin", origin)
	}
	if len(c.exposedHeaders) > 0 {
		headers.Set("Access-Control-Expose-Headers", strings.Join(c.exposedHeaders, ", "))
	}
	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}
	c.logf("  Actual response added headers: %v", headers)
}

// convenience method. checks if a logger is set.
func (c *Cors) logf(format string, a ...interface{}) {
	if c.Log != nil {
		c.Log.Printf(format, a...)
	}
}

// check the Origin of a request. No origin at all is also allowed.
func (c *Cors) OriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return c.isOriginAllowed(r, origin)
}

// isOriginAllowed checks if a given origin is allowed to perform cross-domain requests
// on the endpoint
func (c *Cors) isOriginAllowed(r *http.Request, origin string) bool {
	if c.allowOriginRequestFunc != nil {
		return c.allowOriginRequestFunc(r, origin)
	}
	if c.allowOriginFunc != nil {
		return c.allowOriginFunc(origin)
	}
	if c.allowedOriginsAll {
		return true
	}
	origin = strings.ToLower(origin)
	for _, o := range c.allowedOrigins {
		if o == origin {
			return true
		}
	}
	for _, w := range c.allowedWOrigins {
		if w.match(origin) {
			return true
		}
	}
	return false
}

// isMethodAllowed checks if a given method can be used as part of a cross-domain request
// on the endpoint
func (c *Cors) isMethodAllowed(method string) bool {
	if len(c.allowedMethods) == 0 {
		// If no method allowed, always return false, even for preflight request
		return false
	}
	method = strings.ToUpper(method)
	if method == http.MethodOptions {
		// Always allow preflight requests
		return true
	}
	for _, m := range c.allowedMethods {
		if m == method {
			return true
		}
	}
	return false
}

// areHeadersAllowed checks if a given list of headers are allowed to used within
// a cross-domain request.
func (c *Cors) areHeadersAllowed(requestedHeaders []string) bool {
	if c.allowedHeadersAll || len(requestedHeaders) == 0 {
		return true
	}
	for _, header := range requestedHeaders {
		header = http.CanonicalHeaderKey(header)
		found := false
		for _, h := range c.allowedHeaders {
			if h == header {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
