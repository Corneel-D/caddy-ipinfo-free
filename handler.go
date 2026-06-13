package caddyipinfofree

import (
	"errors"
	"net/netip"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	ID_MODULE_HANDLER = "http.handlers.ipinfo-free"
)

// Let xcaddy know, there is something to do here
func init() {
	caddy.RegisterModule(IPInfoFreeHandler{})
	httpcaddyfile.RegisterHandlerDirective("ipinfo_free", parseCaddyfileHandler)
}

type MMDBResult = map[string]any

type IPInfoFreeHandler struct {
	Mode string `json:"mode,omitempty"`

	ctx   caddy.Context    `json:"-"`
	state *IPInfoFreeState `json:"-"`
}

// CaddyModule returns the Caddy module information
func (IPInfoFreeHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ID_MODULE_HANDLER,
		New: func() caddy.Module { return new(IPInfoFreeHandler) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *IPInfoFreeHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume directive as we only have one anway
	d.Next()
	// Consume next argument optionally as mode
	d.Args(&m.Mode)
	// We don't expected more arguments
	if d.NextArg() {
		return d.ArgErr()
	}

	return nil
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m IPInfoFreeHandler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (m *IPInfoFreeHandler) Validate() error {
	return nil
}

func (m *IPInfoFreeHandler) Provision(ctx caddy.Context) error {
	// Extract the ipinfo free state that is provisioned globally
	app, err := ctx.App(ID_MODULE_STATE)
	if err != nil {
		return errors.New("failed to retrieve state")
	}
	m.state = app.(*IPInfoFreeState)
	// Remember the context of the provisioning
	m.ctx = ctx

	return nil
}

func (m *IPInfoFreeHandler) lookupIP(ip netip.Addr) (*MMDBResult, error) {
	// If there is an uninitialized ip, ignore lookup request
	if !ip.IsValid() {
		return nil, errors.New("IP cannot be nil for lookup")
	}
	// If there is no database, ignore lookup request
	if m.state.db == nil {
		return nil, errors.New("no database found")
	}
	// Allocate lookup record result
	var record MMDBResult
	// Query database by given ip
	err := m.state.db.Lookup(ip).Decode(&record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func (m *IPInfoFreeHandler) getClientIP(r *http.Request) (netip.Addr, error) {
	// Handle value depending on mode
	switch m.Mode {
	case "", "enabled", "true", "on", "1", "strict":
		return m.getRemoteAddr(r)
	case "forwarded":
		// Read ip from official header
		if header := r.Header.Get("X-Forwarded-For"); header != "" {
			return netip.ParseAddr(header)
		}
	case "trusted":
		// Read ip from official header if it comes from a trusted proxy
		trustedProxy := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
		if header := r.Header.Get("X-Forwarded-For"); header != "" && trustedProxy {
			return netip.ParseAddr(header)
		}
	default:
		// Get the caddy replacer and replace all placeholders within mode
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		if ipCandidate := repl.ReplaceAll(m.Mode, ""); ipCandidate == "" {
			if m.state.ErrorOnInvalidIP {
				m.state.logger.Warn("ipinfo_free directive maps to an empty value, defaulting to remote address")
			}
		} else {
			return netip.ParseAddr(ipCandidate)
		}
	}

	return m.getRemoteAddr(r)
}

func (m *IPInfoFreeHandler) getRemoteAddr(r *http.Request) (netip.Addr, error) {
	remoteAddrPort, err := netip.ParseAddrPort(r.RemoteAddr);
	
	if err == nil {
		return remoteAddrPort.Addr(), nil
	}

	return netip.ParseAddr(r.RemoteAddr)
}

func (m IPInfoFreeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch m.Mode {
	case "disabled", "false", "off", "0":
		break
	case "", "enabled", "true", "on", "1", "strict", "forwarded", "trusted":
		fallthrough
	default:
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

		ip, err := m.getClientIP(r)

		var geoip *MMDBResult
		// Only lookup when we got an IP
		if err == nil {
			geoip, err = m.lookupIP(ip)
		}

		if err != nil {
			repl.Set("ipinfo_free.error", err.Error())

			// Make sure to be silent when invalid ip is presented and it is configured to be silent
			if m.state.ErrorOnInvalidIP {
				m.state.logger.Error(err.Error())
			}

			return next.ServeHTTP(w, r)
		}

		repl.Set("ipinfo_free.error", nil)
		repl.Set("ipinfo_free.ip", ip.String())

		for key, value := range *geoip {
			repl.Set("ipinfo_free."+key, value)
		}
	}

	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Module                = (*IPInfoFreeHandler)(nil)
	_ caddy.Provisioner           = (*IPInfoFreeHandler)(nil)
	_ caddy.Validator             = (*IPInfoFreeHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPInfoFreeHandler)(nil)
	_ caddyfile.Unmarshaler       = (*IPInfoFreeHandler)(nil)
)
