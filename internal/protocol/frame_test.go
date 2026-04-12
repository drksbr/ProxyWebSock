package protocol

import (
	"bytes"
	"testing"
)

func TestWindowPacketRoundTrip(t *testing.T) {
	packet, err := EncodeWindowUpdatePacket(WindowUpdate{
		StreamID: 42,
		Delta:    65536,
	})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	header, body, err := ParsePacket(packet)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	update, err := DecodeWindowUpdatePacket(header, body)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if update.StreamID != 42 {
		t.Fatalf("unexpected stream id: %d", update.StreamID)
	}
	if update.Delta != 65536 {
		t.Fatalf("unexpected delta: %d", update.Delta)
	}
}

func TestDialResponseRoundTrip(t *testing.T) {
	packet, err := EncodeDialResponsePacket(DialResponse{
		StreamID:         77,
		DialAddress:      "10.0.0.1:443",
		ResolutionSource: "override",
	})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	header, body, err := ParsePacket(packet)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	resp, err := DecodeDialResponsePacket(header, body)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if resp.StreamID != 77 {
		t.Fatalf("unexpected stream id: %d", resp.StreamID)
	}
	if resp.DialAddress != "10.0.0.1:443" {
		t.Fatalf("unexpected dial address: %s", resp.DialAddress)
	}
	if resp.ResolutionSource != "override" {
		t.Fatalf("unexpected source: %s", resp.ResolutionSource)
	}
}

func TestDiagnosticResponseRoundTrip(t *testing.T) {
	packet, err := EncodeDiagnosticResponsePacket(DiagnosticResponse{
		RequestID:  91,
		StartedAt:  100,
		FinishedAt: 250,
		Error:      "tls handshake failed",
		Steps: []DiagnosticStepResult{
			{
				Step:             "resolve",
				Success:          true,
				DurationMillis:   5,
				ResolutionSource: "override",
				Addresses:        []string{"10.0.0.1"},
			},
			{
				Step:            "tls",
				Success:         false,
				DurationMillis:  120,
				Message:         "unknown authority",
				SelectedAddress: "10.0.0.1:443",
				TLSServerName:   "aghuse.saude.ba.gov.br",
				TLSVersion:      "TLS 1.3",
				TLSCipherSuite:  "TLS_AES_128_GCM_SHA256",
				TLSPeerNames:    []string{"aghuse.saude.ba.gov.br"},
			},
		},
	})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	header, body, err := ParsePacket(packet)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	resp, err := DecodeDiagnosticResponsePacket(header, body)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if resp.RequestID != 91 {
		t.Fatalf("unexpected request id: %d", resp.RequestID)
	}
	if len(resp.Steps) != 2 {
		t.Fatalf("unexpected step count: %d", len(resp.Steps))
	}
	if resp.Steps[0].ResolutionSource != "override" {
		t.Fatalf("unexpected resolution source: %s", resp.Steps[0].ResolutionSource)
	}
	if resp.Steps[1].TLSServerName != "aghuse.saude.ba.gov.br" {
		t.Fatalf("unexpected tls server name: %s", resp.Steps[1].TLSServerName)
	}
	if len(resp.Steps[1].TLSPeerNames) != 1 || resp.Steps[1].TLSPeerNames[0] != "aghuse.saude.ba.gov.br" {
		t.Fatalf("unexpected peer names: %#v", resp.Steps[1].TLSPeerNames)
	}
}

func BenchmarkEncodeDataPacket(b *testing.B) {
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncodeDataPacket(123, payload); err != nil {
			b.Fatalf("encode failed: %v", err)
		}
	}
}

func BenchmarkEncodeDataPacketPooled(b *testing.B) {
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, release, err := EncodeDataPacketPooled(123, payload)
		if err != nil {
			b.Fatalf("encode failed: %v", err)
		}
		if len(buf) == 0 {
			b.Fatal("unexpected empty packet")
		}
		release()
	}
}

func BenchmarkParseDataPacket(b *testing.B) {
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	packet, err := EncodeDataPacket(123, payload)
	if err != nil {
		b.Fatalf("encode failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		streamID, gotPayload, err := DecodeDataPacket(packet)
		if err != nil {
			b.Fatalf("decode failed: %v", err)
		}
		if streamID != 123 {
			b.Fatalf("unexpected stream id: %d", streamID)
		}
		if len(gotPayload) != len(payload) {
			b.Fatalf("unexpected payload len %d", len(gotPayload))
		}
	}
}

func BenchmarkReadPacketPooled(b *testing.B) {
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	packet, err := EncodeDataPacket(123, payload)
	if err != nil {
		b.Fatalf("encode failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(packet)
		header, gotPayload, release, err := ReadPacketPooled(reader, len(packet))
		if err != nil {
			b.Fatalf("read failed: %v", err)
		}
		if header.StreamID != 123 {
			b.Fatalf("unexpected stream id: %d", header.StreamID)
		}
		if len(gotPayload) != len(payload) {
			b.Fatalf("unexpected payload len %d", len(gotPayload))
		}
		release()
	}
}
