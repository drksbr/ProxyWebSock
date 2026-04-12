package protocol

import "testing"

func FuzzDecodeDataPacket(f *testing.F) {
	seed, err := EncodeDataPacket(7, []byte("seed"))
	if err != nil {
		f.Fatalf("encode seed failed: %v", err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		streamID, payload, err := DecodeDataPacket(data)
		if err != nil {
			return
		}
		encoded, release, err := EncodeDataPacketPooled(streamID, payload)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}
		decodedID, decodedPayload, err := DecodeDataPacket(encoded)
		release()
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if decodedID != streamID {
			t.Fatalf("stream id mismatch: %d vs %d", streamID, decodedID)
		}
		if len(decodedPayload) != len(payload) {
			t.Fatalf("payload length mismatch: got %d want %d", len(decodedPayload), len(payload))
		}
	})
}
