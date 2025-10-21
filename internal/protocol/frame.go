package protocol

import (
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
)

type FrameType string

const (
	FrameTypeRegister FrameType = "register"
	FrameTypeDial     FrameType = "dial"
	FrameTypeWrite    FrameType = "write"
	FrameTypeClose    FrameType = "close"
	FrameTypeError    FrameType = "err"
)

type Frame struct {
	Type     FrameType `json:"type"`
	AgentID  string    `json:"agentId,omitempty"`
	Token    string    `json:"token,omitempty"`
	StreamID string    `json:"streamId,omitempty"`
	Host     string    `json:"host,omitempty"`
	Port     int       `json:"port,omitempty"`
	Payload  string    `json:"payload,omitempty"`
	Error    string    `json:"error,omitempty"`
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
	u, err := uuid.Parse(streamID)
	if err != nil {
		return nil, fmt.Errorf("invalid stream id %q: %w", streamID, err)
	}
	buf := make([]byte, 16+len(payload))
	copy(buf[:16], u[:])
	copy(buf[16:], payload)
	return buf, nil
}

func DecodeBinaryFrame(data []byte) (string, []byte, error) {
	if len(data) < 16 {
		return "", nil, fmt.Errorf("binary frame too short: %d", len(data))
	}
	var u uuid.UUID
	copy(u[:], data[:16])
	return u.String(), data[16:], nil
}
