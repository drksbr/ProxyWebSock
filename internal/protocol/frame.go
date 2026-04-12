package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
)

const (
	PacketVersion    = 1
	packetHeaderSize = 16
)

type PacketType uint8

const (
	PacketTypeRegister PacketType = 1 + iota
	PacketTypeDialRequest
	PacketTypeDialResponse
	PacketTypeData
	PacketTypeWindowUpdate
	PacketTypeClose
	PacketTypeHeartbeat
	PacketTypeUpdate
	PacketTypeDiagnosticRequest
	PacketTypeDiagnosticResponse
)

type PacketHeader struct {
	Version  uint8
	Type     PacketType
	Flags    uint16
	StreamID uint64
	BodyLen  uint32
}

const heartbeatFlagHasStats uint16 = 1 << 0

type CloseCode uint16

const (
	CloseCodeOK CloseCode = iota
	CloseCodeDialFailed
	CloseCodeBackpressure
	CloseCodeProtocol
	CloseCodeRemoteError
	CloseCodeShutdown
)

type RegisterRequest struct {
	AgentID string
	Token   string
	Version string
	GOOS    string
	GOARCH  string
}

type DialRequest struct {
	StreamID        uint64
	Host            string
	Port            uint16
	OverrideAddress string
}

type DialResponse struct {
	StreamID         uint64
	DialAddress      string
	ResolutionSource string
	Error            string
}

type DiagnosticRequest struct {
	RequestID       uint64
	Host            string
	Port            uint16
	OverrideAddress string
	TLSServerName   string
	TimeoutMillis   uint32
	TLSEnabled      bool
	TLSSkipVerify   bool
}

type DiagnosticResponse struct {
	RequestID  uint64
	StartedAt  int64
	FinishedAt int64
	Error      string
	Steps      []DiagnosticStepResult
}

type DiagnosticStepResult struct {
	Step             string
	Success          bool
	DurationMillis   uint32
	Message          string
	ResolutionSource string
	Addresses        []string
	SelectedAddress  string
	TLSServerName    string
	TLSVersion       string
	TLSCipherSuite   string
	TLSPeerNames     []string
}

type WindowUpdate struct {
	StreamID uint64
	Delta    uint32
}

type ClosePacket struct {
	StreamID uint64
	Code     CloseCode
	Message  string
}

type HeartbeatMode uint8

const (
	HeartbeatModePing HeartbeatMode = 1
	HeartbeatModePong HeartbeatMode = 2
)

type HeartbeatStats struct {
	RTTMillis           float64
	JitterMillis        float64
	ConsecutiveFailures int
	LastError           string
	LastErrorAt         int64
	Pending             int
	SendDelayMillis     float64
	ControlQueueDepth   int
	DataQueueDepth      int
	CPUPercent          float64
	RSSBytes            uint64
	Goroutines          int
}

type HeartbeatPayload struct {
	Sequence uint64
	SentAt   int64
	Mode     HeartbeatMode
	Stats    *HeartbeatStats
}

const maxPooledPacketSize = 1024 * 1024

var packetBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 128*1024)
	},
}

func EncodePacket(packetType PacketType, streamID uint64, flags uint16, body []byte) ([]byte, error) {
	buf, release, err := EncodePacketPooled(packetType, streamID, flags, body)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	release()
	return out, nil
}

func EncodePacketPooled(packetType PacketType, streamID uint64, flags uint16, body []byte) ([]byte, func(), error) {
	if len(body) > math.MaxUint32 {
		return nil, nil, fmt.Errorf("packet body too large: %d", len(body))
	}
	total := packetHeaderSize + len(body)
	buf := borrowPacketBuffer(total)
	frame := buf[:total]
	encodeHeader(frame[:packetHeaderSize], PacketHeader{
		Version:  PacketVersion,
		Type:     packetType,
		Flags:    flags,
		StreamID: streamID,
		BodyLen:  uint32(len(body)),
	})
	copy(frame[packetHeaderSize:], body)
	return frame, func() {
		releasePacketBuffer(buf)
	}, nil
}

func EncodeDataPacket(streamID uint64, payload []byte) ([]byte, error) {
	return EncodePacket(PacketTypeData, streamID, 0, payload)
}

func EncodeDataPacketPooled(streamID uint64, payload []byte) ([]byte, func(), error) {
	return EncodePacketPooled(PacketTypeData, streamID, 0, payload)
}

func ParsePacket(data []byte) (PacketHeader, []byte, error) {
	if len(data) < packetHeaderSize {
		return PacketHeader{}, nil, fmt.Errorf("packet too short: %d", len(data))
	}
	header, err := decodeHeader(data[:packetHeaderSize])
	if err != nil {
		return PacketHeader{}, nil, err
	}
	total := packetHeaderSize + int(header.BodyLen)
	if len(data) != total {
		return PacketHeader{}, nil, fmt.Errorf("packet length mismatch: have %d want %d", len(data), total)
	}
	return header, data[packetHeaderSize:], nil
}

func ReadPacketPooled(r io.Reader, maxSize int) (PacketHeader, []byte, func(), error) {
	if r == nil {
		return PacketHeader{}, nil, nil, fmt.Errorf("packet reader is nil")
	}
	if maxSize <= 0 {
		maxSize = maxPooledPacketSize
	}
	initialSize := 128 * 1024
	if maxSize < initialSize {
		initialSize = maxSize
	}
	buf := borrowPacketBuffer(initialSize)
	length := 0

	for {
		if length == cap(buf) {
			if length >= maxSize {
				releasePacketBuffer(buf)
				return PacketHeader{}, nil, nil, fmt.Errorf("packet exceeds limit %d", maxSize)
			}
			nextCap := cap(buf) * 2
			if nextCap == 0 {
				nextCap = initialSize
			}
			if nextCap > maxSize {
				nextCap = maxSize
			}
			grown := make([]byte, length, nextCap)
			copy(grown, buf[:length])
			releasePacketBuffer(buf)
			buf = grown[:length]
		}

		readBuf := buf[:cap(buf)]
		n, err := r.Read(readBuf[length:])
		length += n
		buf = readBuf[:length]
		if err == nil {
			continue
		}
		if err == io.EOF {
			break
		}
		releasePacketBuffer(buf)
		return PacketHeader{}, nil, nil, err
	}

	header, body, err := ParsePacket(buf)
	if err != nil {
		releasePacketBuffer(buf)
		return PacketHeader{}, nil, nil, err
	}

	return header, body, func() {
		releasePacketBuffer(buf)
	}, nil
}

func WritePacket(w io.Writer, packetType PacketType, streamID uint64, flags uint16, body []byte) error {
	if w == nil {
		return fmt.Errorf("packet writer is nil")
	}
	if len(body) > math.MaxUint32 {
		return fmt.Errorf("packet body too large: %d", len(body))
	}
	var header [packetHeaderSize]byte
	encodeHeader(header[:], PacketHeader{
		Version:  PacketVersion,
		Type:     packetType,
		Flags:    flags,
		StreamID: streamID,
		BodyLen:  uint32(len(body)),
	})
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}

func WriteDataPacket(w io.Writer, streamID uint64, payload []byte) error {
	return WritePacket(w, PacketTypeData, streamID, 0, payload)
}

func EncodeRegisterPacket(req RegisterRequest) ([]byte, error) {
	body, err := marshalRegisterRequest(req)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTypeRegister, 0, 0, body)
}

func DecodeRegisterPacket(header PacketHeader, body []byte) (RegisterRequest, error) {
	if header.Type != PacketTypeRegister {
		return RegisterRequest{}, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return unmarshalRegisterRequest(body)
}

func EncodeDialRequestPacket(req DialRequest) ([]byte, error) {
	body, err := marshalDialRequest(req)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTypeDialRequest, req.StreamID, 0, body)
}

func DecodeDialRequestPacket(header PacketHeader, body []byte) (DialRequest, error) {
	if header.Type != PacketTypeDialRequest {
		return DialRequest{}, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return unmarshalDialRequest(header.StreamID, body)
}

func EncodeDialResponsePacket(resp DialResponse) ([]byte, error) {
	body, err := marshalDialResponse(resp)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTypeDialResponse, resp.StreamID, 0, body)
}

func DecodeDialResponsePacket(header PacketHeader, body []byte) (DialResponse, error) {
	if header.Type != PacketTypeDialResponse {
		return DialResponse{}, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return unmarshalDialResponse(header.StreamID, body)
}

func EncodeWindowUpdatePacket(update WindowUpdate) ([]byte, error) {
	body := make([]byte, 0, 4)
	body = appendUint32(body, update.Delta)
	return EncodePacket(PacketTypeWindowUpdate, update.StreamID, 0, body)
}

func DecodeWindowUpdatePacket(header PacketHeader, body []byte) (WindowUpdate, error) {
	if header.Type != PacketTypeWindowUpdate {
		return WindowUpdate{}, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	dec := packetDecoder{data: body}
	delta, err := dec.uint32()
	if err != nil {
		return WindowUpdate{}, err
	}
	if err := dec.finish(); err != nil {
		return WindowUpdate{}, err
	}
	return WindowUpdate{
		StreamID: header.StreamID,
		Delta:    delta,
	}, nil
}

func EncodeClosePacket(closePacket ClosePacket) ([]byte, error) {
	body, err := marshalClosePacket(closePacket)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTypeClose, closePacket.StreamID, 0, body)
}

func DecodeClosePacket(header PacketHeader, body []byte) (ClosePacket, error) {
	if header.Type != PacketTypeClose {
		return ClosePacket{}, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return unmarshalClosePacket(header.StreamID, body)
}

func EncodeHeartbeatPacket(payload *HeartbeatPayload) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("heartbeat payload is required")
	}
	body, flags, err := marshalHeartbeatPayload(payload)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTypeHeartbeat, 0, flags, body)
}

func DecodeHeartbeatPacket(header PacketHeader, body []byte) (*HeartbeatPayload, error) {
	if header.Type != PacketTypeHeartbeat {
		return nil, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return unmarshalHeartbeatPayload(header.Flags, body)
}

func EncodeUpdatePacket() ([]byte, error) {
	return EncodePacket(PacketTypeUpdate, 0, 0, nil)
}

func EncodeDiagnosticRequestPacket(req DiagnosticRequest) ([]byte, error) {
	body, err := marshalDiagnosticRequest(req)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTypeDiagnosticRequest, req.RequestID, 0, body)
}

func DecodeDiagnosticRequestPacket(header PacketHeader, body []byte) (DiagnosticRequest, error) {
	if header.Type != PacketTypeDiagnosticRequest {
		return DiagnosticRequest{}, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return unmarshalDiagnosticRequest(header.StreamID, body)
}

func EncodeDiagnosticResponsePacket(resp DiagnosticResponse) ([]byte, error) {
	body, err := marshalDiagnosticResponse(resp)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTypeDiagnosticResponse, resp.RequestID, 0, body)
}

func DecodeDiagnosticResponsePacket(header PacketHeader, body []byte) (DiagnosticResponse, error) {
	if header.Type != PacketTypeDiagnosticResponse {
		return DiagnosticResponse{}, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return unmarshalDiagnosticResponse(header.StreamID, body)
}

func DecodeDataPacket(data []byte) (uint64, []byte, error) {
	header, body, err := ParsePacket(data)
	if err != nil {
		return 0, nil, err
	}
	if header.Type != PacketTypeData {
		return 0, nil, fmt.Errorf("unexpected packet type %d", header.Type)
	}
	return header.StreamID, body, nil
}

func marshalRegisterRequest(req RegisterRequest) ([]byte, error) {
	body := make([]byte, 0, len(req.AgentID)+len(req.Token)+len(req.Version)+len(req.GOOS)+len(req.GOARCH)+10)
	var err error
	body, err = appendString(body, req.AgentID)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, req.Token)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, req.Version)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, req.GOOS)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, req.GOARCH)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func unmarshalRegisterRequest(body []byte) (RegisterRequest, error) {
	dec := packetDecoder{data: body}
	agentID, err := dec.string()
	if err != nil {
		return RegisterRequest{}, err
	}
	token, err := dec.string()
	if err != nil {
		return RegisterRequest{}, err
	}
	version, err := dec.string()
	if err != nil {
		return RegisterRequest{}, err
	}
	goos, err := dec.string()
	if err != nil {
		return RegisterRequest{}, err
	}
	goarch, err := dec.string()
	if err != nil {
		return RegisterRequest{}, err
	}
	if err := dec.finish(); err != nil {
		return RegisterRequest{}, err
	}
	return RegisterRequest{
		AgentID: agentID,
		Token:   token,
		Version: version,
		GOOS:    goos,
		GOARCH:  goarch,
	}, nil
}

func marshalDialRequest(req DialRequest) ([]byte, error) {
	body := make([]byte, 0, len(req.Host)+len(req.OverrideAddress)+6)
	body = appendUint16(body, req.Port)
	var err error
	body, err = appendString(body, req.Host)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, req.OverrideAddress)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func unmarshalDialRequest(streamID uint64, body []byte) (DialRequest, error) {
	dec := packetDecoder{data: body}
	port, err := dec.uint16()
	if err != nil {
		return DialRequest{}, err
	}
	host, err := dec.string()
	if err != nil {
		return DialRequest{}, err
	}
	overrideAddress, err := dec.string()
	if err != nil {
		return DialRequest{}, err
	}
	if err := dec.finish(); err != nil {
		return DialRequest{}, err
	}
	return DialRequest{
		StreamID:        streamID,
		Host:            host,
		Port:            port,
		OverrideAddress: overrideAddress,
	}, nil
}

func marshalDialResponse(resp DialResponse) ([]byte, error) {
	body := make([]byte, 0, len(resp.DialAddress)+len(resp.ResolutionSource)+len(resp.Error)+6)
	var err error
	body, err = appendString(body, resp.DialAddress)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, resp.ResolutionSource)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, resp.Error)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func unmarshalDialResponse(streamID uint64, body []byte) (DialResponse, error) {
	dec := packetDecoder{data: body}
	dialAddress, err := dec.string()
	if err != nil {
		return DialResponse{}, err
	}
	resolutionSource, err := dec.string()
	if err != nil {
		return DialResponse{}, err
	}
	respErr, err := dec.string()
	if err != nil {
		return DialResponse{}, err
	}
	if err := dec.finish(); err != nil {
		return DialResponse{}, err
	}
	return DialResponse{
		StreamID:         streamID,
		DialAddress:      dialAddress,
		ResolutionSource: resolutionSource,
		Error:            respErr,
	}, nil
}

func marshalDiagnosticRequest(req DiagnosticRequest) ([]byte, error) {
	body := make([]byte, 0, len(req.Host)+len(req.OverrideAddress)+len(req.TLSServerName)+12)
	body = appendUint16(body, req.Port)
	body = appendUint32(body, req.TimeoutMillis)
	body = appendBool(body, req.TLSEnabled)
	body = appendBool(body, req.TLSSkipVerify)
	var err error
	body, err = appendString(body, req.Host)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, req.OverrideAddress)
	if err != nil {
		return nil, err
	}
	body, err = appendString(body, req.TLSServerName)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func unmarshalDiagnosticRequest(requestID uint64, body []byte) (DiagnosticRequest, error) {
	dec := packetDecoder{data: body}
	port, err := dec.uint16()
	if err != nil {
		return DiagnosticRequest{}, err
	}
	timeoutMillis, err := dec.uint32()
	if err != nil {
		return DiagnosticRequest{}, err
	}
	tlsEnabled, err := dec.bool()
	if err != nil {
		return DiagnosticRequest{}, err
	}
	tlsSkipVerify, err := dec.bool()
	if err != nil {
		return DiagnosticRequest{}, err
	}
	host, err := dec.string()
	if err != nil {
		return DiagnosticRequest{}, err
	}
	overrideAddress, err := dec.string()
	if err != nil {
		return DiagnosticRequest{}, err
	}
	tlsServerName, err := dec.string()
	if err != nil {
		return DiagnosticRequest{}, err
	}
	if err := dec.finish(); err != nil {
		return DiagnosticRequest{}, err
	}
	return DiagnosticRequest{
		RequestID:       requestID,
		Host:            host,
		Port:            port,
		OverrideAddress: overrideAddress,
		TLSServerName:   tlsServerName,
		TimeoutMillis:   timeoutMillis,
		TLSEnabled:      tlsEnabled,
		TLSSkipVerify:   tlsSkipVerify,
	}, nil
}

func marshalDiagnosticResponse(resp DiagnosticResponse) ([]byte, error) {
	body := make([]byte, 0, len(resp.Error)+len(resp.Steps)*128+24)
	body = appendInt64(body, resp.StartedAt)
	body = appendInt64(body, resp.FinishedAt)
	var err error
	body, err = appendString(body, resp.Error)
	if err != nil {
		return nil, err
	}
	if len(resp.Steps) > math.MaxUint16 {
		return nil, fmt.Errorf("too many diagnostic steps: %d", len(resp.Steps))
	}
	body = appendUint16(body, uint16(len(resp.Steps)))
	for _, step := range resp.Steps {
		body = appendBool(body, step.Success)
		body = appendUint32(body, step.DurationMillis)
		body, err = appendString(body, step.Step)
		if err != nil {
			return nil, err
		}
		body, err = appendString(body, step.Message)
		if err != nil {
			return nil, err
		}
		body, err = appendString(body, step.ResolutionSource)
		if err != nil {
			return nil, err
		}
		body, err = appendString(body, step.SelectedAddress)
		if err != nil {
			return nil, err
		}
		body, err = appendString(body, step.TLSServerName)
		if err != nil {
			return nil, err
		}
		body, err = appendString(body, step.TLSVersion)
		if err != nil {
			return nil, err
		}
		body, err = appendString(body, step.TLSCipherSuite)
		if err != nil {
			return nil, err
		}
		body, err = appendStringSlice(body, step.Addresses)
		if err != nil {
			return nil, err
		}
		body, err = appendStringSlice(body, step.TLSPeerNames)
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

func unmarshalDiagnosticResponse(requestID uint64, body []byte) (DiagnosticResponse, error) {
	dec := packetDecoder{data: body}
	startedAt, err := dec.int64()
	if err != nil {
		return DiagnosticResponse{}, err
	}
	finishedAt, err := dec.int64()
	if err != nil {
		return DiagnosticResponse{}, err
	}
	respErr, err := dec.string()
	if err != nil {
		return DiagnosticResponse{}, err
	}
	stepCount, err := dec.uint16()
	if err != nil {
		return DiagnosticResponse{}, err
	}
	steps := make([]DiagnosticStepResult, 0, int(stepCount))
	for i := 0; i < int(stepCount); i++ {
		success, err := dec.bool()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		durationMillis, err := dec.uint32()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		stepName, err := dec.string()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		message, err := dec.string()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		resolutionSource, err := dec.string()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		selectedAddress, err := dec.string()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		tlsServerName, err := dec.string()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		tlsVersion, err := dec.string()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		tlsCipherSuite, err := dec.string()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		addresses, err := dec.stringSlice()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		peerNames, err := dec.stringSlice()
		if err != nil {
			return DiagnosticResponse{}, err
		}
		steps = append(steps, DiagnosticStepResult{
			Step:             stepName,
			Success:          success,
			DurationMillis:   durationMillis,
			Message:          message,
			ResolutionSource: resolutionSource,
			Addresses:        addresses,
			SelectedAddress:  selectedAddress,
			TLSServerName:    tlsServerName,
			TLSVersion:       tlsVersion,
			TLSCipherSuite:   tlsCipherSuite,
			TLSPeerNames:     peerNames,
		})
	}
	if err := dec.finish(); err != nil {
		return DiagnosticResponse{}, err
	}
	return DiagnosticResponse{
		RequestID:  requestID,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		Error:      respErr,
		Steps:      steps,
	}, nil
}

func marshalClosePacket(closePacket ClosePacket) ([]byte, error) {
	body := make([]byte, 0, len(closePacket.Message)+4)
	body = appendUint16(body, uint16(closePacket.Code))
	var err error
	body, err = appendString(body, closePacket.Message)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func unmarshalClosePacket(streamID uint64, body []byte) (ClosePacket, error) {
	dec := packetDecoder{data: body}
	code, err := dec.uint16()
	if err != nil {
		return ClosePacket{}, err
	}
	message, err := dec.string()
	if err != nil {
		return ClosePacket{}, err
	}
	if err := dec.finish(); err != nil {
		return ClosePacket{}, err
	}
	return ClosePacket{
		StreamID: streamID,
		Code:     CloseCode(code),
		Message:  message,
	}, nil
}

func marshalHeartbeatPayload(payload *HeartbeatPayload) ([]byte, uint16, error) {
	body := make([]byte, 0, 96)
	body = append(body, byte(payload.Mode))
	body = appendUint64(body, payload.Sequence)
	body = appendInt64(body, payload.SentAt)
	flags := uint16(0)
	if payload.Stats != nil {
		flags |= heartbeatFlagHasStats
		body = appendUint64(body, math.Float64bits(payload.Stats.RTTMillis))
		body = appendUint64(body, math.Float64bits(payload.Stats.JitterMillis))
		body = appendUint32(body, uint32(payload.Stats.ConsecutiveFailures))
		body = appendInt64(body, payload.Stats.LastErrorAt)
		body = appendUint32(body, uint32(payload.Stats.Pending))
		body = appendUint64(body, math.Float64bits(payload.Stats.SendDelayMillis))
		body = appendUint32(body, uint32(payload.Stats.ControlQueueDepth))
		body = appendUint32(body, uint32(payload.Stats.DataQueueDepth))
		body = appendUint64(body, math.Float64bits(payload.Stats.CPUPercent))
		body = appendUint64(body, payload.Stats.RSSBytes)
		body = appendUint32(body, uint32(payload.Stats.Goroutines))
		var err error
		body, err = appendString(body, payload.Stats.LastError)
		if err != nil {
			return nil, 0, err
		}
	}
	return body, flags, nil
}

func unmarshalHeartbeatPayload(flags uint16, body []byte) (*HeartbeatPayload, error) {
	dec := packetDecoder{data: body}
	mode, err := dec.uint8()
	if err != nil {
		return nil, err
	}
	sequence, err := dec.uint64()
	if err != nil {
		return nil, err
	}
	sentAt, err := dec.int64()
	if err != nil {
		return nil, err
	}
	payload := &HeartbeatPayload{
		Sequence: sequence,
		SentAt:   sentAt,
		Mode:     HeartbeatMode(mode),
	}
	if flags&heartbeatFlagHasStats != 0 {
		rttBits, err := dec.uint64()
		if err != nil {
			return nil, err
		}
		jitterBits, err := dec.uint64()
		if err != nil {
			return nil, err
		}
		failures, err := dec.uint32()
		if err != nil {
			return nil, err
		}
		lastErrorAt, err := dec.int64()
		if err != nil {
			return nil, err
		}
		pending, err := dec.uint32()
		if err != nil {
			return nil, err
		}
		sendDelayBits, err := dec.uint64()
		if err != nil {
			return nil, err
		}
		controlDepth, err := dec.uint32()
		if err != nil {
			return nil, err
		}
		dataDepth, err := dec.uint32()
		if err != nil {
			return nil, err
		}
		cpuBits, err := dec.uint64()
		if err != nil {
			return nil, err
		}
		rssBytes, err := dec.uint64()
		if err != nil {
			return nil, err
		}
		goroutines, err := dec.uint32()
		if err != nil {
			return nil, err
		}
		lastError, err := dec.string()
		if err != nil {
			return nil, err
		}
		payload.Stats = &HeartbeatStats{
			RTTMillis:           math.Float64frombits(rttBits),
			JitterMillis:        math.Float64frombits(jitterBits),
			ConsecutiveFailures: int(failures),
			LastError:           lastError,
			LastErrorAt:         lastErrorAt,
			Pending:             int(pending),
			SendDelayMillis:     math.Float64frombits(sendDelayBits),
			ControlQueueDepth:   int(controlDepth),
			DataQueueDepth:      int(dataDepth),
			CPUPercent:          math.Float64frombits(cpuBits),
			RSSBytes:            rssBytes,
			Goroutines:          int(goroutines),
		}
	}
	if err := dec.finish(); err != nil {
		return nil, err
	}
	return payload, nil
}

func borrowPacketBuffer(size int) []byte {
	buf := packetBufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func releasePacketBuffer(buf []byte) {
	if buf == nil {
		return
	}
	if cap(buf) > maxPooledPacketSize {
		return
	}
	packetBufferPool.Put(buf[:0])
}

func encodeHeader(dst []byte, header PacketHeader) {
	dst[0] = header.Version
	dst[1] = byte(header.Type)
	binary.BigEndian.PutUint16(dst[2:4], header.Flags)
	binary.BigEndian.PutUint64(dst[4:12], header.StreamID)
	binary.BigEndian.PutUint32(dst[12:16], header.BodyLen)
}

func decodeHeader(data []byte) (PacketHeader, error) {
	if len(data) < packetHeaderSize {
		return PacketHeader{}, fmt.Errorf("packet header too short: %d", len(data))
	}
	version := data[0]
	if version != PacketVersion {
		return PacketHeader{}, fmt.Errorf("unsupported packet version %d", version)
	}
	return PacketHeader{
		Version:  version,
		Type:     PacketType(data[1]),
		Flags:    binary.BigEndian.Uint16(data[2:4]),
		StreamID: binary.BigEndian.Uint64(data[4:12]),
		BodyLen:  binary.BigEndian.Uint32(data[12:16]),
	}, nil
}

func appendUint16(dst []byte, value uint16) []byte {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], value)
	return append(dst, raw[:]...)
}

func appendUint32(dst []byte, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return append(dst, raw[:]...)
}

func appendUint64(dst []byte, value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return append(dst, raw[:]...)
}

func appendInt64(dst []byte, value int64) []byte {
	return appendUint64(dst, uint64(value))
}

func appendBool(dst []byte, value bool) []byte {
	if value {
		return append(dst, 1)
	}
	return append(dst, 0)
}

func appendString(dst []byte, value string) ([]byte, error) {
	if len(value) > math.MaxUint16 {
		return nil, fmt.Errorf("string too long: %d", len(value))
	}
	dst = appendUint16(dst, uint16(len(value)))
	dst = append(dst, value...)
	return dst, nil
}

func appendStringSlice(dst []byte, values []string) ([]byte, error) {
	if len(values) > math.MaxUint16 {
		return nil, fmt.Errorf("too many strings: %d", len(values))
	}
	dst = appendUint16(dst, uint16(len(values)))
	var err error
	for _, value := range values {
		dst, err = appendString(dst, value)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

type packetDecoder struct {
	data []byte
	pos  int
}

func (d *packetDecoder) uint8() (uint8, error) {
	if len(d.data)-d.pos < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	value := d.data[d.pos]
	d.pos++
	return value, nil
}

func (d *packetDecoder) uint16() (uint16, error) {
	if len(d.data)-d.pos < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint16(d.data[d.pos : d.pos+2])
	d.pos += 2
	return value, nil
}

func (d *packetDecoder) uint32() (uint32, error) {
	if len(d.data)-d.pos < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint32(d.data[d.pos : d.pos+4])
	d.pos += 4
	return value, nil
}

func (d *packetDecoder) uint64() (uint64, error) {
	if len(d.data)-d.pos < 8 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint64(d.data[d.pos : d.pos+8])
	d.pos += 8
	return value, nil
}

func (d *packetDecoder) int64() (int64, error) {
	value, err := d.uint64()
	return int64(value), err
}

func (d *packetDecoder) string() (string, error) {
	length, err := d.uint16()
	if err != nil {
		return "", err
	}
	if len(d.data)-d.pos < int(length) {
		return "", io.ErrUnexpectedEOF
	}
	value := string(d.data[d.pos : d.pos+int(length)])
	d.pos += int(length)
	return value, nil
}

func (d *packetDecoder) bool() (bool, error) {
	value, err := d.uint8()
	if err != nil {
		return false, err
	}
	return value != 0, nil
}

func (d *packetDecoder) stringSlice() ([]string, error) {
	count, err := d.uint16()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	values := make([]string, 0, int(count))
	for i := 0; i < int(count); i++ {
		value, err := d.string()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func (d *packetDecoder) finish() error {
	if d.pos != len(d.data) {
		return fmt.Errorf("unexpected trailing bytes: %d", len(d.data)-d.pos)
	}
	return nil
}
