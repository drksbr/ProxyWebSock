package protocol

import (
	"encoding/base64"
	"fmt"
)

type FrameType string

const (
	FrameTypeRegister  FrameType = "register"
	FrameTypeDial      FrameType = "dial"
	FrameTypeWrite     FrameType = "write"
	FrameTypeClose     FrameType = "close"
	FrameTypeError     FrameType = "err"
	FrameTypeHeartbeat FrameType = "heartbeat"
)

type Frame struct {
	Type      FrameType         `json:"type"`
	AgentID   string            `json:"agentId,omitempty"`
	Token     string            `json:"token,omitempty"`
	StreamID  string            `json:"streamId,omitempty"`
	Host      string            `json:"host,omitempty"`
	Port      int               `json:"port,omitempty"`
	Payload   string            `json:"payload,omitempty"`
	Error     string            `json:"error,omitempty"`
	Heartbeat *HeartbeatPayload `json:"heartbeat,omitempty"`
}

func EncodePayload(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func DecodePayload(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}
	return data, nil
}

func EncodeBinaryFrame(streamID string, payload []byte) ([]byte, error) {
	idLen := len(streamID)
	if idLen == 0 || idLen > 255 {
		return nil, fmt.Errorf("invalid stream id length %d", idLen)
	}
	buf := make([]byte, 1+idLen+len(payload))
	buf[0] = byte(idLen)
	copy(buf[1:1+idLen], streamID)
	copy(buf[1+idLen:], payload)
	return buf, nil
}

func DecodeBinaryFrame(data []byte) (string, []byte, error) {
	if len(data) < 1 {
		return "", nil, fmt.Errorf("binary frame missing stream id length")
	}
	idLen := int(data[0])
	if idLen == 0 {
		return "", nil, fmt.Errorf("binary frame has zero-length stream id")
	}
	if len(data) < 1+idLen {
		return "", nil, fmt.Errorf("binary frame too short for stream id: have %d need %d", len(data), 1+idLen)
	}
	streamID := string(data[1 : 1+idLen])
	return streamID, data[1+idLen:], nil
}

type HeartbeatMode string

const (
	HeartbeatModePing HeartbeatMode = "ping"
	HeartbeatModePong HeartbeatMode = "pong"
)

type HeartbeatStats struct {
	RTTMillis           float64 `json:"rttMillis,omitempty"`
	JitterMillis        float64 `json:"jitterMillis,omitempty"`
	ConsecutiveFailures int     `json:"consecutiveFailures,omitempty"`
	LastError           string  `json:"lastError,omitempty"`
	LastErrorAt         int64   `json:"lastErrorAt,omitempty"`
}

type HeartbeatPayload struct {
	Sequence uint64          `json:"seq"`
	SentAt   int64           `json:"sentAt"`
	Mode     HeartbeatMode   `json:"mode,omitempty"`
	Stats    *HeartbeatStats `json:"stats,omitempty"`
}
