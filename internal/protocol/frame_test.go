package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFrameWindowJSONRoundTrip(t *testing.T) {
	frame := Frame{
		Type:     FrameTypeWindow,
		StreamID: "stream-1",
		Window:   65536,
	}

	data, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Frame
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Type != FrameTypeWindow {
		t.Fatalf("unexpected type: %s", decoded.Type)
	}
	if decoded.StreamID != frame.StreamID {
		t.Fatalf("unexpected stream id: %s", decoded.StreamID)
	}
	if decoded.Window != frame.Window {
		t.Fatalf("unexpected window: %d", decoded.Window)
	}
}

func BenchmarkEncodeBinaryFrame(b *testing.B) {
	streamID := "benchmark-stream"
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncodeBinaryFrame(streamID, payload); err != nil {
			b.Fatalf("encode failed: %v", err)
		}
	}
}

func BenchmarkEncodeBinaryFramePooled(b *testing.B) {
	streamID := "benchmark-stream"
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, release, err := EncodeBinaryFramePooled(streamID, payload)
		if err != nil {
			b.Fatalf("encode failed: %v", err)
		}
		if len(buf) == 0 {
			b.Fatalf("unexpected empty buffer")
		}
		release()
	}
}

func BenchmarkDecodeBinaryFrame(b *testing.B) {
	streamID := "benchmark-stream"
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	frame, err := EncodeBinaryFrame(streamID, payload)
	if err != nil {
		b.Fatalf("encode failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		gotStreamID, gotPayload, err := DecodeBinaryFrame(frame)
		if err != nil {
			b.Fatalf("decode failed: %v", err)
		}
		if gotStreamID != streamID {
			b.Fatalf("unexpected stream id: %s", gotStreamID)
		}
		if len(gotPayload) != len(payload) {
			b.Fatalf("unexpected payload len %d", len(gotPayload))
		}
	}
}

func BenchmarkReadBinaryFramePooled(b *testing.B) {
	streamID := "benchmark-stream"
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	frame, err := EncodeBinaryFrame(streamID, payload)
	if err != nil {
		b.Fatalf("encode failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(frame)
		gotStreamID, gotPayload, release, err := ReadBinaryFramePooled(reader, len(frame))
		if err != nil {
			b.Fatalf("read failed: %v", err)
		}
		if gotStreamID != streamID {
			b.Fatalf("unexpected stream id: %s", gotStreamID)
		}
		if len(gotPayload) != len(payload) {
			b.Fatalf("unexpected payload len %d", len(gotPayload))
		}
		release()
	}
}
