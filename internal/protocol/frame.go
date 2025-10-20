package protocol

import (
	"encoding/base64"
	"fmt"
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
