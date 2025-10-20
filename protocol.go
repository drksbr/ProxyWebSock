package main

import (
	"encoding/base64"
	"fmt"
)

type frameType string

const (
	frameTypeRegister frameType = "register"
	frameTypeDial     frameType = "dial"
	frameTypeWrite    frameType = "write"
	frameTypeClose    frameType = "close"
	frameTypeError    frameType = "err"
)

type frame struct {
	Type     frameType `json:"type"`
	AgentID  string    `json:"agentId,omitempty"`
	Token    string    `json:"token,omitempty"`
	StreamID string    `json:"streamId,omitempty"`
	Host     string    `json:"host,omitempty"`
	Port     int       `json:"port,omitempty"`
	Payload  string    `json:"payload,omitempty"`
	Error    string    `json:"error,omitempty"`
}

func encodePayload(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func decodePayload(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}
	return data, nil
}
