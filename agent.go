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
	u, _ := url.Parse(cfg.RelayWSS)
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   cfg.ReadBuf,
		WriteBufferSize:  cfg.WriteBuf,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: false}, // ajuste conforme seu certificado
	}
	ws, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()
	log.Println("[agent] conectado ao relay:", cfg.RelayWSS)

	// registra
	if err := ws.WriteJSON(frame{Op: "register", AgentID: cfg.AgentID, Token: cfg.Token}); err != nil {
		return err
	}

	streams := make(map[string]*aStream)

	// leitor do relay
	errCh := make(chan error, 1)
	go func() {
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			if mt != websocket.TextMessage {
				continue
			}
			var f frame
			if json.Unmarshal(data, &f) != nil {
				continue
			}
			switch f.Op {
			case "dial":
				go func(f frame) {
					addr := net.JoinHostPort(f.Host, strconv.Itoa(f.Port))
					conn, err := net.DialTimeout("tcp", addr, cfg.DialTO)
					if err != nil {
						_ = ws.WriteJSON(frame{Op: "err", StreamID: f.StreamID, Message: err.Error()})
						return
					}
					streams[f.StreamID] = &aStream{Conn: conn}
					// destino interno -> relay
					go func(id string, c net.Conn) {
						r := bufio.NewReader(c)
						buf := make([]byte, cfg.ReadBuf)
						for {
							n, err := r.Read(buf)
							if n > 0 {
								_ = ws.WriteJSON(frame{Op: "write", StreamID: id, Payload: base64.StdEncoding.EncodeToString(buf[:n])})
							}
							if err != nil {
								break
							}
						}
						_ = ws.WriteJSON(frame{Op: "close", StreamID: id})
						_ = c.Close()
						delete(streams, id)
					}(f.StreamID, conn)
				}(f)
			case "write":
				if s, ok := streams[f.StreamID]; ok {
					if p, err := base64.StdEncoding.DecodeString(f.Payload); err == nil && len(p) > 0 {
						_, _ = s.Conn.Write(p)
					}
				}
			case "close":
				if s, ok := streams[f.StreamID]; ok {
					_ = s.Conn.Close()
					delete(streams, f.StreamID)
				}
			}
		}
	}()

	// keepalive
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ping.C:
			_ = ws.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
		case err := <-errCh:
			return err
		}
	}
}
