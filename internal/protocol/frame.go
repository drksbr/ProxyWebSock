package protocol

import (
	"encoding/base64"
	"fmt"
	"sync"
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
	buf, release, err := EncodeBinaryFramePooled(streamID, payload)
	if err != nil {
		return nil, err
	}
	copyBuf := make([]byte, len(buf))
	copy(copyBuf, buf)
	release()
	return copyBuf, nil
}

const maxPooledFrameSize = 1024 * 1024

var binaryFramePool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 64*1024)
	},
}

// EncodeBinaryFramePooled encodes the stream identifier and payload using a pooled backing buffer.
// The caller MUST invoke the returned release function exactly once after the slice is no longer needed.
func EncodeBinaryFramePooled(streamID string, payload []byte) ([]byte, func(), error) {
	idLen := len(streamID)
	if idLen == 0 || idLen > 255 {
		return nil, nil, fmt.Errorf("invalid stream id length %d", idLen)
	}
	total := 1 + idLen + len(payload)
	buf := borrowFrameBuffer(total)
	frame := buf[:total]
	frame[0] = byte(idLen)
	copy(frame[1:1+idLen], streamID)
	copy(frame[1+idLen:], payload)
	release := func() {
		releaseFrameBuffer(buf)
	}
	return frame, release, nil
}

func borrowFrameBuffer(size int) []byte {
	buf := binaryFramePool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func releaseFrameBuffer(buf []byte) {
	if buf == nil {
		return
	}
	if cap(buf) > maxPooledFrameSize {
		return
	}
	binaryFramePool.Put(buf[:0])
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
	Pending             int     `json:"pending,omitempty"`
	SendDelayMillis     float64 `json:"sendDelayMillis,omitempty"`
	ControlQueueDepth   int     `json:"controlQueueDepth,omitempty"`
	DataQueueDepth      int     `json:"dataQueueDepth,omitempty"`
	CPUPercent          float64 `json:"cpuPercent,omitempty"`
	RSSBytes            uint64  `json:"rssBytes,omitempty"`
	Goroutines          int     `json:"goroutines,omitempty"`
}

type HeartbeatPayload struct {
	Sequence uint64          `json:"seq"`
	SentAt   int64           `json:"sentAt"`
	Mode     HeartbeatMode   `json:"mode,omitempty"`
	Stats    *HeartbeatStats `json:"stats,omitempty"`
}
