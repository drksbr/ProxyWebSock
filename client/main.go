package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/net/proxy"
)

type UpstreamRewrite struct {
	Host        string // ex: aghuse.saude.ba.gov.br
	Origin      string // ex: https://aghuse.saude.ba.gov.br
	RefererBase string // ex: https://aghuse.saude.ba.gov.br/aghu/
}

func main() {
	wd, _ := os.Getwd()
	log.Printf("WD=%s", wd)

	if err := godotenv.Overload(".env"); err != nil {
		log.Println("⚠️  .env não encontrado neste diretório; usando variáveis do sistema")
	}

	// Upstream base (SEM path)
	targetStr := mustEnv("INTRANET_TARGET_URL") // ex: https://aghuse.saude.ba.gov.br
	targetURL, err := url.Parse(targetStr)
	if err != nil {
		log.Fatalf("INTRANET_TARGET_URL inválida: %v", err)
	}
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		log.Fatalf("INTRANET_TARGET_URL precisa ser http:// ou https:// (veio: %q)", targetURL.Scheme)
	}
	targetURL.Path, targetURL.RawPath, targetURL.RawQuery, targetURL.Fragment = "", "", "", ""

	// Base interna completa (inclui /aghu/) para rewrite de Location/cookies
	internalBaseURL := mustURL("INTERNAL_BASE_URL") // ex: https://aghuse.saude.ba.gov.br/aghu/

	// Contexto do app no upstream
	upstreamContext := normalizeContextPath(envOr("UPSTREAM_CONTEXT_PATH", "/aghu"))

	// Opcional: forçar o que o upstream “enxerga”
	rew := UpstreamRewrite{
		Host:        strings.TrimSpace(os.Getenv("UPSTREAM_HOST")),
		Origin:      strings.TrimSpace(os.Getenv("UPSTREAM_ORIGIN")),
		RefererBase: strings.TrimSpace(os.Getenv("UPSTREAM_REFERER_BASE")),
	}
	if rew.Host == "" {
		rew.Host = targetURL.Hostname()
	}
	if rew.Origin == "" {
		rew.Origin = targetURL.Scheme + "://" + rew.Host
	}
	if rew.RefererBase == "" {
		// base default: https://<host>/aghu/
		rew.RefererBase = rew.Origin + upstreamContext + "/"
	}
	rew.RefererBase = ensureTrailingSlash(rew.RefererBase)

	// SOCKS5
	socksAddr := mustEnv("SOCKS5_ADDR")
	socksUser := envOr("SOCKS5_USER", "")
	socksPass := envOr("SOCKS5_PASS", "")

	// Auth pública (para seu daemon)
	publicUser := mustEnv("PUBLIC_USER")
	publicPass := mustEnv("PUBLIC_PASS")

	// TLS upstream
	tlsCfg, err := buildUpstreamTLSConfig()
	if err != nil {
		log.Fatalf("falha ao montar TLS upstream: %v", err)
	}

	transport, err := socks5Transport(socksAddr, socksUser, socksPass, tlsCfg)
	if err != nil {
		log.Fatalf("falha ao configurar SOCKS5: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicBase := publicBaseFromRequest(r)

		// Proxy por request (thread-safe)
		rp := newReverseProxy(targetURL, transport, internalBaseURL, publicBase, upstreamContext, rew)

		withBasicAuth(rp, publicUser, publicPass).ServeHTTP(w, r)
	})

	addr := envOr("LISTEN_ADDR", ":8081")
	log.Printf("listening on %s (public) -> %s (upstream) via SOCKS5 %s", addr, targetURL.String(), socksAddr)
	log.Printf("upstream host mask: host=%s origin=%s refererBase=%s", rew.Host, rew.Origin, rew.RefererBase)

	log.Fatal(http.ListenAndServe(addr, handler))
}

func newReverseProxy(
	targetURL *url.URL,
	transport http.RoundTripper,
	internalBase *url.URL,
	publicBase *url.URL,
	upstreamContext string,
	rew UpstreamRewrite,
) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.Transport = transport

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		// Capture host/proto do cliente (público) antes de mexer no req
		publicHost := req.Host
		publicProto := "http"
		if req.TLS != nil {
			publicProto = "https"
		}
		if xfProto := strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")); xfProto != "" {
			publicProto = xfProto
		}
		if xfHost := strings.TrimSpace(req.Header.Get("X-Forwarded-Host")); xfHost != "" {
			publicHost = xfHost
		}

		originalDirector(req)

		// ✅ Contexto /aghu no upstream
		req.URL.Path = ensureContext(req.URL.Path, upstreamContext)

		// ✅ Host/SNI do upstream: aqui você decide se quer mascarar Host pro upstream
		// - req.URL.Host já é o targetURL.Host (NewSingleHostReverseProxy)
		// - req.Host controla o header Host enviado ao upstream
		req.Host = rew.Host

		// ✅ Reescrita de headers sensíveis (muito comum em validação de login/CSRF)
		rewriteOriginReferer(req, rew)

		// ✅ X-Forwarded-* coerentes (o app pode usar isso)
		req.Header.Set("X-Forwarded-For", clientIP(req))
		req.Header.Set("X-Forwarded-Proto", publicProto)
		req.Header.Set("X-Forwarded-Host", publicHost)

		// Alguns servidores olham "Forwarded"
		req.Header.Set("Forwarded", `for=`+clientIP(req)+`;proto=`+publicProto+`;host=`+publicHost)

		// (Opcional) se o upstream reclamar de Accept-Encoding (debug), descomente:
		// req.Header.Del("Accept-Encoding")
	}

	rp.ModifyResponse = func(resp *http.Response) error {
		// Redirects e cookies Domain para manter tudo no seu domínio público
		rewriteLocation(resp, internalBase, publicBase)
		rewriteSetCookieDomain(resp, internalBase.Hostname(), publicBase.Hostname())
		return nil
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("upstream error: %v", e)
		http.Error(w, "Upstream indisponível", http.StatusBadGateway)
	}

	return rp
}

func rewriteOriginReferer(req *http.Request, rew UpstreamRewrite) {
	// Origin (POST do login geralmente tem)
	if origin := req.Header.Get("Origin"); origin != "" {
		req.Header.Set("Origin", rew.Origin)
	}

	// Referer (muitos frameworks checam)
	if ref := req.Header.Get("Referer"); ref != "" {
		// se o ref é público, troca a base pelo upstream
		// Ex: https://aghuse.neurocirurgiahgrs.com.br/aghu/login.xhtml -> https://aghuse.saude.ba.gov.br/aghu/login.xhtml
		req.Header.Set("Referer", mapPublicToUpstreamRef(ref, rew))
	}

	// Host já foi setado no Director (req.Host = rew.Host)
}

func mapPublicToUpstreamRef(ref string, rew UpstreamRewrite) string {
	// tenta parsear e reconstruir no domínio do upstream mantendo path/query
	u, err := url.Parse(ref)
	if err != nil {
		// fallback: aponta para referer base
		return rew.RefererBase
	}
	// mantém o path/query do referer público, mas joga no host upstream
	u.Scheme = "https"
	u.Host = rew.Host
	// garante que está sob /aghu (se vier sem)
	if !strings.HasPrefix(u.Path, "/aghu/") && u.Path != "/aghu" {
		u.Path = "/aghu" + u.Path
	}
	return u.String()
}

// --- Helpers de context/path/base

func ensureContext(path, context string) string {
	if path == "" || path == "/" {
		return context + "/"
	}
	if path == context || strings.HasPrefix(path, context+"/") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return context + path
}

func normalizeContextPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/aghu"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func ensureTrailingSlash(s string) string {
	if strings.HasSuffix(s, "/") {
		return s
	}
	return s + "/"
}

func publicBaseFromRequest(r *http.Request) *url.URL {
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return &url.URL{Scheme: scheme, Host: host, Path: "/"}
}

// --- Redirect / Cookie rewrite

func rewriteLocation(resp *http.Response, internalBase, publicBase *url.URL) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}

	if strings.HasPrefix(loc, internalBase.String()) {
		newLoc := publicBase.String() + strings.TrimPrefix(loc, internalBase.String())
		resp.Header.Set("Location", newLoc)
		return
	}

	internalHostPrefix := internalBase.Scheme + "://" + internalBase.Host
	if strings.HasPrefix(loc, internalHostPrefix) {
		publicHostPrefix := publicBase.Scheme + "://" + publicBase.Host
		newLoc := publicHostPrefix + strings.TrimPrefix(loc, internalHostPrefix)
		resp.Header.Set("Location", newLoc)
		return
	}
}

func rewriteSetCookieDomain(resp *http.Response, internalDomain, publicDomain string) {
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}

	out := make([]string, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, replaceCookieDomain(c, internalDomain, publicDomain))
	}

	resp.Header.Del("Set-Cookie")
	for _, c := range out {
		resp.Header.Add("Set-Cookie", c)
	}
}

func replaceCookieDomain(setCookie, internalDomain, publicDomain string) string {
	lower := strings.ToLower(setCookie)
	idx := strings.Index(lower, "domain=")
	if idx < 0 {
		return setCookie
	}

	start := idx + len("domain=")
	end := start
	for end < len(setCookie) && setCookie[end] != ';' {
		end++
	}

	current := strings.TrimSpace(setCookie[start:end])
	currentTrim := strings.TrimPrefix(current, ".")

	if strings.EqualFold(currentTrim, internalDomain) {
		prefixDot := ""
		if strings.HasPrefix(current, ".") {
			prefixDot = "."
		}
		return setCookie[:start] + prefixDot + publicDomain + setCookie[end:]
	}

	return setCookie
}

// --- SOCKS5 Transport

func socks5Transport(addr, user, pass string, tlsCfg *tls.Config) (*http.Transport, error) {
	var auth *proxy.Auth
	if user != "" || pass != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}

	dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		type dctx interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}
		if dc, ok := dialer.(dctx); ok {
			return dc.DialContext(ctx, network, address)
		}
		return dialer.Dial(network, address)
	}

	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialContext(ctx, network, addr)
		},
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		ForceAttemptHTTP2:     true,
	}, nil
}

// --- TLS Upstream

func buildUpstreamTLSConfig() (*tls.Config, error) {
	insecure := strings.EqualFold(strings.TrimSpace(os.Getenv("UPSTREAM_INSECURE_SKIP_VERIFY")), "true")
	caPath := strings.TrimSpace(os.Getenv("UPSTREAM_CA_PEM"))

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if insecure {
		cfg.InsecureSkipVerify = true
		log.Println("⚠️  UPSTREAM_INSECURE_SKIP_VERIFY=true (INSEGURO). Use apenas para POC.")
		return cfg, nil
	}

	if caPath == "" {
		return cfg, nil
	}

	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return nil, errors.New("não foi possível adicionar certificados do PEM (arquivo inválido?)")
	}

	cfg.RootCAs = pool
	log.Printf("✅ CA interna carregada de %s", caPath)
	return cfg, nil
}

// --- Basic Auth (seu daemon)

func withBasicAuth(next http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- misc

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("variável %s obrigatória", k)
	}
	return v
}

func mustURL(k string) *url.URL {
	raw := mustEnv(k)
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("%s inválida: %v", k, err)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u
}

func envOr(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
