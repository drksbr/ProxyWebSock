package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

type frame struct {
	Op       string `json:"op"`
	StreamID string `json:"streamId,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Payload  string `json:"payload,omitempty"`
	AgentID  string `json:"agentId,omitempty"`
	Token    string `json:"token,omitempty"`
	Message  string `json:"message,omitempty"`
}

type streamWriter interface {
	Write(b []byte) (int, error)
	Close() error
}

type agentConn struct {
	id      string
	token   string
	ws      *websocket.Conn
	streams sync.Map // streamId -> streamWriter
}

var (
	relayListenAddr  string
	relayAgentsKV    string // "id:token,id2:token2"
	relayACLRegexes  []string
	relayMetricsAddr string
	maxFrameBytes    int
	wsIdleSeconds    int
	connectDialTOms  int

	upgrader = websocket.Upgrader{
		// WS vindo do agente
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	agents     sync.Map // agentID -> *agentConn
	agentCreds sync.Map // agentID -> token

	// métricas simples
	wsAgentsConnected int64
	httpActiveConns   int64
	bytesUp           uint64 // navegador -> intranet
	bytesDown         uint64 // intranet -> navegador
	dialErrors        uint64
	authFailures      uint64
)

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Inicia o servidor público (WS /tunnel + HTTP CONNECT proxy)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// carregar creds
		for _, p := range strings.Split(relayAgentsKV, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			kv := strings.SplitN(p, ":", 2)
			if len(kv) != 2 {
				log.Fatalf("AGENTS malformado: %q", p)
			}
			agentCreds.Store(kv[0], kv[1])
		}

		// WS /tunnel
		mux := http.NewServeMux()
		mux.HandleFunc("/tunnel", tunnelWS)

		// CONNECT proxy na raiz
		mux.HandleFunc("/", connectProxy)

		// métricas
		go func() {
			if relayMetricsAddr == "" {
				return
			}
			http.HandleFunc("/metrics", metricsHandler)
			log.Println("[metrics] escutando em", relayMetricsAddr, "GET /metrics")
			if err := http.ListenAndServe(relayMetricsAddr, nil); err != nil {
				log.Println("[metrics] erro:", err)
			}
		}()

		log.Println("[relay] escutando em", relayListenAddr, "(use TLS com seu proxy reverso)")
		s := &http.Server{
			Addr:         relayListenAddr,
			Handler:      mux,
			ReadTimeout:  0,
			WriteTimeout: 0,
		}
		return s.ListenAndServe()
	},
}

func init() {
	relayCmd.Flags().StringVar(&relayListenAddr, "listen", ":3000", "endereço para escutar (HTTP claro; use TLS no reverso)")
	relayCmd.Flags().StringVar(&relayAgentsKV, "agents", "agente-hospital-01:um-segredo", "mapa agentID:token[,id2:token2]")
	relayCmd.Flags().StringSliceVar(&relayACLRegexes, "acl-allow", []string{`^([a-zA-Z0-9\.-]+):443$`}, "regex(es) permitidos de host:port")
	relayCmd.Flags().StringVar(&relayMetricsAddr, "metrics", ":9091", "endereço para métricas Prometheus (vazio = desabilita)")
	relayCmd.Flags().IntVar(&maxFrameBytes, "max-frame", 128*1024, "tamanho máximo de frame WS (bytes)")
	relayCmd.Flags().IntVar(&wsIdleSeconds, "ws-idle", 120, "tempo inativo do WS (s)")
	relayCmd.Flags().IntVar(&connectDialTOms, "dial-timeout-ms", 10000, "timeout de discagem interna pelo agente (ms)")
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP intra_ws_agents_connected WebSocket agentes conectados\n# TYPE intra_ws_agents_connected gauge\nintra_ws_agents_connected %d\n", atomic.LoadInt64(&wsAgentsConnected))
	fmt.Fprintf(w, "# HELP intra_http_active_conns Conexões CONNECT ativas\n# TYPE intra_http_active_conns gauge\nintra_http_active_conns %d\n", atomic.LoadInt64(&httpActiveConns))
	fmt.Fprintf(w, "# HELP intra_bytes_up Bytes do navegador -> intranet\n# TYPE intra_bytes_up counter\nintra_bytes_up %d\n", atomic.LoadUint64(&bytesUp))
	fmt.Fprintf(w, "# HELP intra_bytes_down Bytes da intranet -> navegador\n# TYPE intra_bytes_down counter\nintra_bytes_down %d\n", atomic.LoadUint64(&bytesDown))
	fmt.Fprintf(w, "# HELP intra_dial_errors Erros de dial no agente\n# TYPE intra_dial_errors counter\nintra_dial_errors %d\n", atomic.LoadUint64(&dialErrors))
	fmt.Fprintf(w, "# HELP intra_proxy_auth_failures Falhas de Proxy-Auth\n# TYPE intra_proxy_auth_failures counter\nintra_proxy_auth_failures %d\n", atomic.LoadUint64(&authFailures))
}

func tunnelWS(w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Duration(wsIdleSeconds) * time.Second))

	// primeiro frame deve ser register
	_, msg, err := c.ReadMessage()
	if err != nil {
		return
	}
	var reg frame
	if json.Unmarshal(msg, &reg) != nil || reg.Op != "register" {
		return
	}
	// valida credencial
	v, ok := agentCreds.Load(reg.AgentID)
	if !ok || v.(string) != reg.Token {
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"op":"err","message":"auth"}`))
		return
	}
	ac := &agentConn{id: reg.AgentID, token: reg.Token, ws: c}
	if old, ok := agents.Load(reg.AgentID); ok {
		// derruba anterior
		_ = old.(*agentConn).ws.Close()
		agents.Delete(reg.AgentID)
		atomic.AddInt64(&wsAgentsConnected, -1)
	}
	agents.Store(reg.AgentID, ac)
	atomic.AddInt64(&wsAgentsConnected, 1)
	log.Printf("[relay] agente %s conectado", reg.AgentID)

	// loop de mensagens do agente
	for {
		mt, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		if mt != websocket.TextMessage {
			continue
		}
		var f frame
		if json.Unmarshal(msg, &f) != nil {
			continue
		}
		switch f.Op {
		case "write":
			if v, ok := ac.streams.Load(f.StreamID); ok {
				dst := v.(streamWriter)
				data, _ := base64.StdEncoding.DecodeString(f.Payload)
				if len(data) > 0 {
					_, _ = dst.Write(data)
					atomic.AddUint64(&bytesDown, uint64(len(data)))
				}
			}
		case "close":
			if v, ok := ac.streams.Load(f.StreamID); ok {
				_ = v.(streamWriter).Close()
				ac.streams.Delete(f.StreamID)
			}
		case "err":
			atomic.AddUint64(&dialErrors, 1)
			if f.StreamID != "" {
				if v, ok := ac.streams.Load(f.StreamID); ok {
					_ = v.(streamWriter).Close()
					ac.streams.Delete(f.StreamID)
				}
			}
		}
	}
	agents.Delete(reg.AgentID)
	atomic.AddInt64(&wsAgentsConnected, -1)
	log.Printf("[relay] agente %s desconectado", reg.AgentID)
}

func connectProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Use CONNECT", http.StatusMethodNotAllowed)
		return
	}
	agentID, token, err := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		atomic.AddUint64(&authFailures, 1)
		w.Header().Set("Proxy-Authenticate", `Basic realm="intra-relay"`)
		http.Error(w, "Proxy Auth Required", 407)
		return
	}
	// valida
	tv, ok := agentCreds.Load(agentID)
	if !ok || tv.(string) != token {
		atomic.AddUint64(&authFailures, 1)
		http.Error(w, "Bad credentials", 407)
		return
	}
	av, ok := agents.Load(agentID)
	if !ok {
		http.Error(w, "Agent offline", 502)
		return
	}
	agent := av.(*agentConn)

	// host:port do CONNECT
	target := r.Host
	host, port, err := splitHostPortDefault(target, 443)
	if err != nil {
		http.Error(w, "Bad target", 400)
		return
	}
	// ACL
	if !aclAllow(host, port) {
		http.Error(w, "Forbidden by ACL", 403)
		return
	}

	// Hijack para tunelar bytes com o cliente (navegador)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijacker", 500)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", 500)
		return
	}
	defer clientConn.Close()

	// 200 Established
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()

	atomic.AddInt64(&httpActiveConns, 1)
	defer atomic.AddInt64(&httpActiveConns, -1)

	streamID := newStreamID()

	// writer do lado do cliente
	sw := &socketWriter{c: clientConn}
	agent.streams.Store(streamID, sw)

	// pede dial ao agente
	_ = agent.ws.WriteJSON(frame{Op: "dial", StreamID: streamID, Host: host, Port: port})

	// Do navegador -> Agente
	go func() {
		// backpressure simples: escrevemos para WS de modo sincrono; se travar, paramos de ler (TCP faz contrapressão)
		br := bufio.NewReader(clientConn)
		buf := make([]byte, 32*1024)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				atomic.AddUint64(&bytesUp, uint64(n))
				for off := 0; off < n; {
					chunk := n - off
					if chunk > maxFrameBytes {
						chunk = maxFrameBytes
					}
					b64 := base64.StdEncoding.EncodeToString(buf[off : off+chunk])
					if err2 := agent.ws.WriteJSON(frame{Op: "write", StreamID: streamID, Payload: b64}); err2 != nil {
						return
					}
					off += chunk
				}
			}
			if err != nil {
				_ = agent.ws.WriteJSON(frame{Op: "close", StreamID: streamID})
				return
			}
		}
	}()

	// aguarda até o cliente fechar (o outro caminho é tratado no WS message -> close)
	// aqui apenas bloqueamos
	<-connClosed(clientConn)
	agent.streams.Delete(streamID)
}

func parseProxyAuth(h string) (id, token string, err error) {
	if h == "" {
		return "", "", errors.New("no auth")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return "", "", errors.New("bad auth")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}
	s := string(raw)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", errors.New("bad auth pair")
	}
	return s[:i], s[i+1:], nil
}

func splitHostPortDefault(hostport string, defPort int) (string, int, error) {
	host := hostport
	port := defPort
	if strings.Contains(hostport, ":") {
		p := strings.Split(hostport, ":")
		host = p[0]
		fmt.Sscanf(p[1], "%d", &port)
	}
	if host == "" || port <= 0 {
		return "", 0, errors.New("bad host/port")
	}
	return host, port, nil
}

func aclAllow(host string, port int) bool {
	s := fmt.Sprintf("%s:%d", host, port)
	for _, re := range relayACLRegexes {
		rx := regexp.MustCompile(re)
		if rx.MatchString(s) {
			return true
		}
	}
	return false
}

type socketWriter struct {
	c net.Conn
}

func (s *socketWriter) Write(b []byte) (int, error) { return s.c.Write(b) }
func (s *socketWriter) Close() error                { return s.c.Close() }

func connClosed(c net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		_ = c.SetReadDeadline(time.Now().Add(365 * 24 * time.Hour)) // não importa
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // vai bloquear até fechar
		close(ch)
	}()
	return ch
}

func newStreamID() string {
	// simples; se quiser, troque por x/crypto/rand base64-url
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
