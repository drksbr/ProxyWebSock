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
		log.Println("[relay] inicializando servidor relay")
		log.Printf("[relay] configuração: listen=%s, metrics=%s, maxFrameBytes=%d, wsIdleSeconds=%d, dialTimeoutMs=%d", relayListenAddr, relayMetricsAddr, maxFrameBytes, wsIdleSeconds, connectDialTOms)
		log.Printf("[relay] ACLs carregadas: %v", relayACLRegexes)
		log.Printf("[relay] agentes declarados em --agents: %q", relayAgentsKV)
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
			log.Printf("[relay] credencial registrada para agente %s", kv[0])
		}

		// WS /tunnel
		mux := http.NewServeMux()
		mux.HandleFunc("/tunnel", tunnelWS)

		// CONNECT proxy na raiz
		mux.HandleFunc("/", connectProxy)

		// métricas
		go func() {
			if relayMetricsAddr == "" {
				log.Println("[relay] métricas desabilitadas (--metrics vazio)")
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
	log.Printf("[metrics] requisição de métricas recebida de %s %s", r.RemoteAddr, r.UserAgent())
	w.Header().Set("content-type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP intra_ws_agents_connected WebSocket agentes conectados\n# TYPE intra_ws_agents_connected gauge\nintra_ws_agents_connected %d\n", atomic.LoadInt64(&wsAgentsConnected))
	fmt.Fprintf(w, "# HELP intra_http_active_conns Conexões CONNECT ativas\n# TYPE intra_http_active_conns gauge\nintra_http_active_conns %d\n", atomic.LoadInt64(&httpActiveConns))
	fmt.Fprintf(w, "# HELP intra_bytes_up Bytes do navegador -> intranet\n# TYPE intra_bytes_up counter\nintra_bytes_up %d\n", atomic.LoadUint64(&bytesUp))
	fmt.Fprintf(w, "# HELP intra_bytes_down Bytes da intranet -> navegador\n# TYPE intra_bytes_down counter\nintra_bytes_down %d\n", atomic.LoadUint64(&bytesDown))
	fmt.Fprintf(w, "# HELP intra_dial_errors Erros de dial no agente\n# TYPE intra_dial_errors counter\nintra_dial_errors %d\n", atomic.LoadUint64(&dialErrors))
	fmt.Fprintf(w, "# HELP intra_proxy_auth_failures Falhas de Proxy-Auth\n# TYPE intra_proxy_auth_failures counter\nintra_proxy_auth_failures %d\n", atomic.LoadUint64(&authFailures))
}

func tunnelWS(w http.ResponseWriter, r *http.Request) {
	log.Printf("[relay][tunnel] nova conexão WebSocket de %s", r.RemoteAddr)
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[relay][tunnel] falha em upgrade para WS de %s: %v", r.RemoteAddr, err)
		http.Error(w, err.Error(), 400)
		return
	}
	log.Printf("[relay][tunnel] upgrade concluído para %s", r.RemoteAddr)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Duration(wsIdleSeconds) * time.Second))

	// primeiro frame deve ser register
	_, msg, err := c.ReadMessage()
	if err != nil {
		log.Printf("[relay][tunnel] erro lendo frame de registro de %s: %v", r.RemoteAddr, err)
		return
	}
	var reg frame
	if json.Unmarshal(msg, &reg) != nil || reg.Op != "register" {
		log.Printf("[relay][tunnel] frame inicial inválido de %s: %s", r.RemoteAddr, string(msg))
		return
	}
	// valida credencial
	v, ok := agentCreds.Load(reg.AgentID)
	if !ok || v.(string) != reg.Token {
		log.Printf("[relay][tunnel] falha de autenticação para agente %s (%s)", reg.AgentID, r.RemoteAddr)
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"op":"err","message":"auth"}`))
		return
	}
	log.Printf("[relay][tunnel] agente %s autenticado com sucesso (%s)", reg.AgentID, r.RemoteAddr)
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
			log.Printf("[relay][tunnel] erro lendo mensagem do agente %s: %v", reg.AgentID, err)
			break
		}
		if mt != websocket.TextMessage {
			log.Printf("[relay][tunnel] ignorando mensagem não textual do agente %s (tipo=%d)", reg.AgentID, mt)
			continue
		}
		var f frame
		if json.Unmarshal(msg, &f) != nil {
			log.Printf("[relay][tunnel] falha ao decodificar frame JSON do agente %s: %s", reg.AgentID, string(msg))
			continue
		}
		log.Printf("[relay][tunnel] frame recebido do agente %s: op=%s stream=%s payload=%d bytes", reg.AgentID, f.Op, f.StreamID, len(f.Payload))
		switch f.Op {
		case "write":
			if v, ok := ac.streams.Load(f.StreamID); ok {
				dst := v.(streamWriter)
				data, decodeErr := base64.StdEncoding.DecodeString(f.Payload)
				if decodeErr != nil {
					log.Printf("[relay][tunnel] erro decodificando payload base64 stream %s agente %s: %v", f.StreamID, reg.AgentID, decodeErr)
					continue
				}
				if len(data) > 0 {
					_, _ = dst.Write(data)
					atomic.AddUint64(&bytesDown, uint64(len(data)))
					log.Printf("[relay][tunnel] stream %s -> cliente (%d bytes) agente=%s", f.StreamID, len(data), reg.AgentID)
				}
			} else {
				log.Printf("[relay][tunnel] write recebido para stream desconhecida %s agente %s", f.StreamID, reg.AgentID)
			}
		case "close":
			if v, ok := ac.streams.Load(f.StreamID); ok {
				_ = v.(streamWriter).Close()
				ac.streams.Delete(f.StreamID)
				log.Printf("[relay][tunnel] stream %s encerrado pelo agente %s", f.StreamID, reg.AgentID)
			} else {
				log.Printf("[relay][tunnel] close recebido para stream desconhecida %s agente %s", f.StreamID, reg.AgentID)
			}
		case "err":
			atomic.AddUint64(&dialErrors, 1)
			if f.StreamID != "" {
				if v, ok := ac.streams.Load(f.StreamID); ok {
					_ = v.(streamWriter).Close()
					ac.streams.Delete(f.StreamID)
					log.Printf("[relay][tunnel] erro reportado para stream %s pelo agente %s: %s", f.StreamID, reg.AgentID, f.Message)
				} else {
					log.Printf("[relay][tunnel] erro reportado para stream desconhecida %s pelo agente %s: %s", f.StreamID, reg.AgentID, f.Message)
				}
			} else {
				log.Printf("[relay][tunnel] erro genérico reportado pelo agente %s: %s", reg.AgentID, f.Message)
			}
		}
	}
	agents.Delete(reg.AgentID)
	atomic.AddInt64(&wsAgentsConnected, -1)
	log.Printf("[relay] agente %s desconectado", reg.AgentID)
}

func connectProxy(w http.ResponseWriter, r *http.Request) {
	log.Printf("[relay][proxy] nova requisição %s %s de %s", r.Method, r.Host, r.RemoteAddr)
	if r.Method != http.MethodConnect {
		log.Printf("[relay][proxy] método inválido %s de %s", r.Method, r.RemoteAddr)
		http.Error(w, "Use CONNECT", http.StatusMethodNotAllowed)
		return
	}
	agentID, token, err := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		atomic.AddUint64(&authFailures, 1)
		w.Header().Set("Proxy-Authenticate", `Basic realm="intra-relay"`)
		log.Printf("[relay][proxy] Proxy-Auth ausente/inválida de %s: %v", r.RemoteAddr, err)
		http.Error(w, "Proxy Auth Required", 407)
		return
	}
	// valida
	tv, ok := agentCreds.Load(agentID)
	if !ok || tv.(string) != token {
		atomic.AddUint64(&authFailures, 1)
		log.Printf("[relay][proxy] credenciais inválidas para agente %s de %s", agentID, r.RemoteAddr)
		http.Error(w, "Bad credentials", 407)
		return
	}
	av, ok := agents.Load(agentID)
	if !ok {
		log.Printf("[relay][proxy] agente %s offline para %s", agentID, r.RemoteAddr)
		http.Error(w, "Agent offline", 502)
		return
	}
	agent := av.(*agentConn)
	log.Printf("[relay][proxy] agente %s disponível para cliente %s", agentID, r.RemoteAddr)

	// host:port do CONNECT
	target := r.Host
	host, port, err := splitHostPortDefault(target, 443)
	if err != nil {
		log.Printf("[relay][proxy] host/porta inválidos %s: %v", target, err)
		http.Error(w, "Bad target", 400)
		return
	}
	// ACL
	if !aclAllow(host, port) {
		log.Printf("[relay][proxy] ACL bloqueou destino %s:%d para agente %s", host, port, agentID)
		http.Error(w, "Forbidden by ACL", 403)
		return
	}
	log.Printf("[relay][proxy] destino permitido %s:%d para agente %s", host, port, agentID)

	// Hijack para tunelar bytes com o cliente (navegador)
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[relay][proxy] hijacker indisponível para %s", r.RemoteAddr)
		http.Error(w, "no hijacker", 500)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Printf("[relay][proxy] hijack falhou para %s: %v", r.RemoteAddr, err)
		http.Error(w, "hijack failed", 500)
		return
	}
	defer clientConn.Close()
	log.Printf("[relay][proxy] hijack concluído para %s", r.RemoteAddr)

	// 200 Established
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()
	log.Printf("[relay][proxy] enviado 200 Connection Established para %s", r.RemoteAddr)

	atomic.AddInt64(&httpActiveConns, 1)
	defer atomic.AddInt64(&httpActiveConns, -1)
	log.Printf("[relay][proxy] conexões ativas agora: %d", atomic.LoadInt64(&httpActiveConns))

	streamID := newStreamID()

	// writer do lado do cliente
	sw := &socketWriter{c: clientConn}
	agent.streams.Store(streamID, sw)
	log.Printf("[relay][proxy] stream %s associado ao cliente %s (agente %s)", streamID, r.RemoteAddr, agentID)

	// pede dial ao agente
	_ = agent.ws.WriteJSON(frame{Op: "dial", StreamID: streamID, Host: host, Port: port})
	log.Printf("[relay][proxy] enviado frame dial stream=%s destino=%s:%d agente=%s", streamID, host, port, agentID)

	// Do navegador -> Agente
	go func() {
		log.Printf("[relay][proxy] iniciando túnel cliente->agente stream %s", streamID)
		// backpressure simples: escrevemos para WS de modo sincrono; se travar, paramos de ler (TCP faz contrapressão)
		br := bufio.NewReader(clientConn)
		buf := make([]byte, 32*1024)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				atomic.AddUint64(&bytesUp, uint64(n))
				log.Printf("[relay][proxy] stream %s cliente->agente leu %d bytes", streamID, n)
				for off := 0; off < n; {
					chunk := n - off
					if chunk > maxFrameBytes {
						chunk = maxFrameBytes
						log.Printf("[relay][proxy] stream %s quebrando chunk para %d bytes (maxFrameBytes)", streamID, chunk)
					}
					b64 := base64.StdEncoding.EncodeToString(buf[off : off+chunk])
					if err2 := agent.ws.WriteJSON(frame{Op: "write", StreamID: streamID, Payload: b64}); err2 != nil {
						log.Printf("[relay][proxy] erro enviando chunk ao agente %s stream %s: %v", agentID, streamID, err2)
						return
					}
					log.Printf("[relay][proxy] stream %s cliente->agente escreveu chunk de %d bytes (base64 len=%d)", streamID, chunk, len(b64))
					off += chunk
				}
			}
			if err != nil {
				_ = agent.ws.WriteJSON(frame{Op: "close", StreamID: streamID})
				log.Printf("[relay][proxy] leitura do cliente %s encerrada stream %s: %v", r.RemoteAddr, streamID, err)
				return
			}
		}
	}()

	// aguarda até o cliente fechar (o outro caminho é tratado no WS message -> close)
	// aqui apenas bloqueamos
	<-connClosed(clientConn)
	log.Printf("[relay][proxy] cliente %s fechou conexão stream %s", r.RemoteAddr, streamID)
	agent.streams.Delete(streamID)
	log.Printf("[relay][proxy] stream %s removido do agente %s", streamID, agentID)
}

func parseProxyAuth(h string) (id, token string, err error) {
	log.Printf("[relay][proxy] parseProxyAuth header length=%d", len(h))
	if h == "" {
		log.Printf("[relay][proxy] parseProxyAuth sem header")
		return "", "", errors.New("no auth")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		log.Printf("[relay][proxy] parseProxyAuth formato inválido (len=%d)", len(h))
		return "", "", errors.New("bad auth")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("[relay][proxy] parseProxyAuth falhou para base64: %v", err)
		return "", "", err
	}
	s := string(raw)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		log.Printf("[relay][proxy] parseProxyAuth par inválido (len=%d)", len(s))
		return "", "", errors.New("bad auth pair")
	}
	log.Printf("[relay][proxy] parseProxyAuth identificou agente %s", s[:i])
	return s[:i], s[i+1:], nil
}

func splitHostPortDefault(hostport string, defPort int) (string, int, error) {
	log.Printf("[relay][proxy] splitHostPortDefault input=%s defPort=%d", hostport, defPort)
	host := hostport
	port := defPort
	if strings.Contains(hostport, ":") {
		p := strings.Split(hostport, ":")
		host = p[0]
		fmt.Sscanf(p[1], "%d", &port)
		log.Printf("[relay][proxy] splitHostPortDefault parse: host=%s port=%d", host, port)
	}
	if host == "" || port <= 0 {
		log.Printf("[relay][proxy] splitHostPortDefault inválido host=%s port=%d", host, port)
		return "", 0, errors.New("bad host/port")
	}
	log.Printf("[relay][proxy] splitHostPortDefault final host=%s port=%d", host, port)
	return host, port, nil
}

func aclAllow(host string, port int) bool {
	s := fmt.Sprintf("%s:%d", host, port)
	log.Printf("[relay][proxy] verificando ACL para %s", s)
	for _, re := range relayACLRegexes {
		rx := regexp.MustCompile(re)
		if rx.MatchString(s) {
			log.Printf("[relay][proxy] ACL %s autorizou %s", re, s)
			return true
		}
		log.Printf("[relay][proxy] ACL %s não casou %s", re, s)
	}
	log.Printf("[relay][proxy] nenhum ACL permitiu %s", s)
	return false
}

type socketWriter struct {
	c net.Conn
}

func (s *socketWriter) Write(b []byte) (int, error) {
	n, err := s.c.Write(b)
	log.Printf("[relay][socketWriter] escreveu %d bytes err=%v", n, err)
	return n, err
}
func (s *socketWriter) Close() error {
	log.Printf("[relay][socketWriter] fechando conexão %s", s.c.RemoteAddr())
	return s.c.Close()
}

func connClosed(c net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		log.Printf("[relay][connClosed] aguardando fechamento de %s", c.RemoteAddr())
		_ = c.SetReadDeadline(time.Now().Add(365 * 24 * time.Hour)) // não importa
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // vai bloquear até fechar
		log.Printf("[relay][connClosed] detectou fechamento de %s", c.RemoteAddr())
		close(ch)
	}()
	return ch
}

func newStreamID() string {
	// simples; se quiser, troque por x/crypto/rand base64-url
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	log.Printf("[relay][stream] gerado streamID %s", id)
	return id
}
