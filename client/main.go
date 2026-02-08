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

func main() {
	wd, _ := os.Getwd()
	log.Printf("WD=%s", wd)

	// Carrega .env do diretório atual e SOBRESCREVE variáveis já existentes no ambiente
	if err := godotenv.Overload(".env"); err != nil {
		log.Println("⚠️  .env não encontrado neste diretório; usando variáveis do sistema")
	}

	// Upstream base: SEM path (importante para evitar duplicação de /aghu)
	targetStr := mustEnv("INTRANET_TARGET_URL") // ex: https://aghuse.saude.ba.gov.br
	targetURL, err := url.Parse(targetStr)
	if err != nil {
		log.Fatalf("INTRANET_TARGET_URL inválida: %v", err)
	}
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		log.Fatalf("INTRANET_TARGET_URL precisa ser http:// ou https:// (veio: %q)", targetURL.Scheme)
	}
	targetURL.Path, targetURL.RawPath, targetURL.RawQuery, targetURL.Fragment = "", "", "", ""

	// Base interna completa (inclui /aghu/) usada para reescrever redirects/cookies
	internalBaseURL := mustURL("INTERNAL_BASE_URL") // ex: https://aghuse.saude.ba.gov.br/aghu/

	// Contexto que deve existir no upstream (ex.: /aghu)
	// Se não setar, default "/aghu"
	upstreamContext := envOr("UPSTREAM_CONTEXT_PATH", "/aghu")
	upstreamContext = normalizeContextPath(upstreamContext)

	// SOCKS5
	socksAddr := mustEnv("SOCKS5_ADDR")
	socksUser := envOr("SOCKS5_USER", "")
	socksPass := envOr("SOCKS5_PASS", "")

	// Auth pública
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

	// Handler cria um proxy por request (thread-safe) e usa base pública dinâmica
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicBase := publicBaseFromRequest(r)
		rp := newReverseProxy(targetURL, transport, internalBaseURL, publicBase, upstreamContext)

		withBasicAuth(rp, publicUser, publicPass).ServeHTTP(w, r)
	})

	addr := envOr("LISTEN_ADDR", ":8081")
	log.Printf("listening on %s -> %s via SOCKS5 %s", addr, targetURL.String(), socksAddr)
	log.Printf("internal base: %s | upstream context: %s | public base: dinâmico por request", internalBaseURL.String(), upstreamContext)

	log.Fatal(http.ListenAndServe(addr, handler))
}

func newReverseProxy(
	targetURL *url.URL,
	transport http.RoundTripper,
	internalBase *url.URL,
	publicBase *url.URL,
	upstreamContext string,
) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.Transport = transport

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)

		// Força Host do upstream correto
		req.Host = targetURL.Host

		// ✅ FIX: garante que qualquer request pública sem /aghu seja enviada para /aghu no upstream
		// Ex.: /pages/x.xhtml -> /aghu/pages/x.xhtml
		req.URL.Path = ensureContext(req.URL.Path, upstreamContext)

		// Encaminhamento padrão
		req.Header.Set("X-Forwarded-For", clientIP(req))

		// Preserva proto/host se vierem do LB (senão define)
		if req.Header.Get("X-Forwarded-Proto") == "" {
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		}
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
	}

	// Rewrite de redirects/cookies usando base pública dinâmica
	rp.ModifyResponse = func(resp *http.Response) error {
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

func ensureContext(path, context string) string {
	// context vem normalizado como "/aghu"
	if path == "" || path == "/" {
		return context + "/"
	}
	if path == context || strings.HasPrefix(path, context+"/") {
		return path
	}
	// Se vier sem a barra inicial, normaliza
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
	// remove trailing slash
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return p
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

func rewriteLocation(resp *http.Response, internalBase, publicBase *url.URL) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}

	// Caso 1: Location absoluto com a base interna completa (inclui /aghu/)
	if strings.HasPrefix(loc, internalBase.String()) {
		newLoc := publicBase.String() + strings.TrimPrefix(loc, internalBase.String())
		resp.Header.Set("Location", newLoc)
		return
	}

	// Caso 2: Location absoluto só com host interno
	internalHostPrefix := internalBase.Scheme + "://" + internalBase.Host
	if strings.HasPrefix(loc, internalHostPrefix) {
		publicHostPrefix := publicBase.Scheme + "://" + publicBase.Host
		newLoc := publicHostPrefix + strings.TrimPrefix(loc, internalHostPrefix)
		resp.Header.Set("Location", newLoc)
		return
	}

	// Caso 3: Location relativo (deixa como está)
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
