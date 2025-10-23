package protocol

import "testing"

func FuzzDecodeBinaryFrame(f *testing.F) {
	seed := []byte{5, 's', 'e', 'e', 'd', '1', '2', '3'}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		streamID, payload, err := DecodeBinaryFrame(data)
		if err != nil {
			return
		}
		encoded, release, err := EncodeBinaryFramePooled(streamID, payload)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}
		decodedID, decodedPayload, err := DecodeBinaryFrame(encoded)
		release()
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if decodedID != streamID {
			t.Fatalf("stream id mismatch: %q vs %q", streamID, decodedID)
		}
		if len(decodedPayload) != len(payload) {
			t.Fatalf("payload length mismatch: got %d want %d", len(decodedPayload), len(payload))
		}
	})
}
