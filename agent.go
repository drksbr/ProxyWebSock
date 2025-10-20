package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

var (
	agentRelayWSS string
	agentID       string
	agentToken    string
	agentDialTOms int
	agentReadBuf  int
	agentWriteBuf int
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Inicia o agente dentro da intranet (conecta no relay via WSS)",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Printf("[agent] iniciando com parâmetros: relay=%s id=%s dialTimeout=%dms readBuf=%d writeBuf=%d", agentRelayWSS, agentID, agentDialTOms, agentReadBuf, agentWriteBuf)
		cfg := agentCfg{
			RelayWSS: agentRelayWSS,
			AgentID:  agentID,
			Token:    agentToken,
			DialTO:   time.Duration(agentDialTOms) * time.Millisecond,
			ReadBuf:  agentReadBuf,
			WriteBuf: agentWriteBuf,
		}
		for {
			if err := agentRunOnce(cfg); err != nil {
				log.Println("[agent]", err)
			}
			log.Println("[agent] aguardando 2s para tentar reconectar ao relay")
			time.Sleep(2 * time.Second)
		}
	},
}

func init() {
	agentCmd.Flags().StringVar(&agentRelayWSS, "relay", "wss://relay.seudominio.com/tunnel", "URL WSS do relay (/tunnel)")
	agentCmd.Flags().StringVar(&agentID, "id", "agente-hospital-01", "Agent ID")
	agentCmd.Flags().StringVar(&agentToken, "token", "um-segredo", "Agent token")
	agentCmd.Flags().IntVar(&agentDialTOms, "dial-timeout-ms", 10000, "timeout de discagem (ms)")
	agentCmd.Flags().IntVar(&agentReadBuf, "read-buf", 32*1024, "buffer de leitura (bytes)")
	agentCmd.Flags().IntVar(&agentWriteBuf, "write-buf", 32*1024, "buffer de escrita (bytes)")
}

type agentCfg struct {
	RelayWSS string
	AgentID  string
	Token    string
	DialTO   time.Duration
	ReadBuf  int
	WriteBuf int
}

type aStream struct {
	Conn net.Conn
}

func agentRunOnce(cfg agentCfg) error {
	log.Printf("[agent] agentRunOnce iniciado: relay=%s id=%s dialTO=%s", cfg.RelayWSS, cfg.AgentID, cfg.DialTO)
	u, _ := url.Parse(cfg.RelayWSS)
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   cfg.ReadBuf,
		WriteBufferSize:  cfg.WriteBuf,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: false}, // ajuste conforme seu certificado
	}
	log.Printf("[agent] abrindo conexão WSS para %s", u.String())
	ws, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		if resp != nil {
			log.Printf("[agent] resposta do relay na falha: status=%s", resp.Status)
		}
		log.Printf("[agent] falha ao conectar ao relay %s: %v", u.String(), err)
		return err
	}
	defer ws.Close()
	var localAddr, remoteAddr string
	if conn := ws.UnderlyingConn(); conn != nil {
		localAddr = conn.LocalAddr().String()
		remoteAddr = conn.RemoteAddr().String()
	}
	log.Printf("[agent] conectado ao relay %s (local=%s remote=%s)", cfg.RelayWSS, localAddr, remoteAddr)

	// registra
	if err := ws.WriteJSON(frame{Op: "register", AgentID: cfg.AgentID, Token: cfg.Token}); err != nil {
		log.Printf("[agent] erro enviando frame register: %v", err)
		return err
	}
	log.Printf("[agent] frame register enviado com sucesso (id=%s)", cfg.AgentID)

	streams := make(map[string]*aStream)
	log.Printf("[agent] mapa de streams inicializado (cap=%d)", len(streams))

	// leitor do relay
	errCh := make(chan error, 1)
	go func() {
		log.Printf("[agent] goroutine de leitura do relay iniciada")
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				log.Printf("[agent] erro lendo mensagem do relay: %v", err)
				errCh <- err
				return
			}
			if mt != websocket.TextMessage {
				log.Printf("[agent] ignorando frame não textual tipo=%d", mt)
				continue
			}
			var f frame
			if json.Unmarshal(data, &f) != nil {
				log.Printf("[agent] frame JSON inválido recebido: %s", string(data))
				continue
			}
			log.Printf("[agent] frame recebido do relay: op=%s stream=%s payload=%d bytes", f.Op, f.StreamID, len(f.Payload))
			switch f.Op {
			case "dial":
				go func(f frame) {
					addr := net.JoinHostPort(f.Host, strconv.Itoa(f.Port))
					log.Printf("[agent] solicitada nova conexão stream=%s destino=%s", f.StreamID, addr)
					conn, err := net.DialTimeout("tcp", addr, cfg.DialTO)
					if err != nil {
						log.Printf("[agent] erro ao conectar no destino %s stream=%s: %v", addr, f.StreamID, err)
						if err := ws.WriteJSON(frame{Op: "err", StreamID: f.StreamID, Message: err.Error()}); err != nil {
							log.Printf("[agent] erro enviando frame err stream=%s: %v", f.StreamID, err)
						}
						return
					}
					streams[f.StreamID] = &aStream{Conn: conn}
					log.Printf("[agent] conexão estabelecida stream=%s destino=%s", f.StreamID, addr)
					// destino interno -> relay
					go func(id string, c net.Conn) {
						log.Printf("[agent] iniciando leitura do destino stream=%s remoto=%s", id, c.RemoteAddr())
						r := bufio.NewReader(c)
						buf := make([]byte, cfg.ReadBuf)
						for {
							n, err := r.Read(buf)
							if n > 0 {
								log.Printf("[agent] stream=%s destino->relay leu %d bytes", id, n)
								if err := ws.WriteJSON(frame{Op: "write", StreamID: id, Payload: base64.StdEncoding.EncodeToString(buf[:n])}); err != nil {
									log.Printf("[agent] erro enviando frame write stream=%s: %v", id, err)
									break
								}
							}
							if err != nil {
								log.Printf("[agent] leitura encerrada stream=%s: %v", id, err)
								break
							}
						}
						if err := ws.WriteJSON(frame{Op: "close", StreamID: id}); err != nil {
							log.Printf("[agent] erro enviando frame close stream=%s: %v", id, err)
						}
						log.Printf("[agent] enviado close stream=%s após término da leitura", id)
						_ = c.Close()
						delete(streams, id)
						log.Printf("[agent] stream=%s removido (restantes=%d)", id, len(streams))
					}(f.StreamID, conn)
				}(f)
			case "write":
				if s, ok := streams[f.StreamID]; ok {
					p, decodeErr := base64.StdEncoding.DecodeString(f.Payload)
					if decodeErr != nil {
						log.Printf("[agent] erro decodificando payload base64 stream=%s: %v", f.StreamID, decodeErr)
						continue
					}
					if len(p) > 0 {
						log.Printf("[agent] stream=%s relay->destino escrevendo %d bytes", f.StreamID, len(p))
						if _, err := s.Conn.Write(p); err != nil {
							log.Printf("[agent] erro escrevendo no destino stream=%s: %v", f.StreamID, err)
						}
					}
				} else {
					log.Printf("[agent] write recebido para stream desconhecida %s", f.StreamID)
				}
			case "close":
				if s, ok := streams[f.StreamID]; ok {
					_ = s.Conn.Close()
					delete(streams, f.StreamID)
					log.Printf("[agent] destino fechou stream=%s (restantes=%d)", f.StreamID, len(streams))
				} else {
					log.Printf("[agent] close recebido para stream desconhecida %s", f.StreamID)
				}
			}
		}
	}()

	// keepalive
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	log.Printf("[agent] ticker de ping iniciado (20s)")

	for {
		select {
		case <-ping.C:
			deadline := time.Now().Add(5 * time.Second)
			if err := ws.WriteControl(websocket.PingMessage, []byte("ping"), deadline); err != nil {
				log.Printf("[agent] erro enviando ping: %v", err)
				return err
			}
			log.Printf("[agent] ping enviado ao relay (deadline=%s)", deadline)
		case err := <-errCh:
			log.Printf("[agent] erro de leitura do relay recebido: %v", err)
			return err
		}
	}
}
