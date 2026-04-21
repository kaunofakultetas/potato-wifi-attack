package bodylogger

import (
	"bytes"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const maxBody = 8192

func init() {
	caddy.RegisterModule(Dumper{})
	httpcaddyfile.RegisterHandlerDirective("dump_body", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		return &Dumper{}, nil
	})
}

type Dumper struct {
	logger *zap.Logger
}

func (Dumper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.dump_body",
		New: func() caddy.Module { return new(Dumper) },
	}
}

func (d *Dumper) Provision(ctx caddy.Context) error {
	d.logger = ctx.Logger()
	return nil
}

func (d *Dumper) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return next.ServeHTTP(w, r)
	}

	buf := &bytes.Buffer{}
	r.Body = &capBody{rc: r.Body, buf: buf, limit: maxBody}

	defer func() {
		body := buf.Bytes()
		if len(body) == 0 {
			return
		}
		d.logger.Info("request body",
			zap.String("remote_ip", r.RemoteAddr),
			zap.String("method", r.Method),
			zap.String("host", r.Host),
			zap.String("uri", r.RequestURI),
			zap.String("content_type", r.Header.Get("Content-Type")),
			zap.Int64("content_length", r.ContentLength),
			zap.String("body", string(body)),
			zap.Bool("truncated", r.ContentLength > int64(len(body))),
		)
	}()

	return next.ServeHTTP(w, r)
}

// capBody is an io.ReadCloser that mirrors the first `limit` bytes it reads
// into buf while passing the full stream through to the downstream reader.
type capBody struct {
	rc    io.ReadCloser
	buf   *bytes.Buffer
	limit int
}

func (c *capBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		remaining := c.limit - c.buf.Len()
		if remaining > 0 {
			w := n
			if w > remaining {
				w = remaining
			}
			c.buf.Write(p[:w])
		}
	}
	return n, err
}

func (c *capBody) Close() error { return c.rc.Close() }

var (
	_ caddy.Provisioner           = (*Dumper)(nil)
	_ caddyhttp.MiddlewareHandler = (*Dumper)(nil)
)
