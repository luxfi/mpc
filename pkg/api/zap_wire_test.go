package api

import (
	"encoding/json"
	"testing"

	"github.com/luxfi/zap"
)

// The frame hanzoai/commerce builds, reproduced here rather than imported —
// commerce is a private module and this is the contract, not an implementation
// detail. If these two ever disagree the wire is broken, which is exactly the
// state this file exists to make impossible to reach silently.
const (
	clientFieldStatus  = 0
	clientFieldPayload = 8
	clientObjectSize   = 16
)

func clientRequest(t *testing.T, opcode uint16, payload []byte) *zap.Message {
	t.Helper()
	b := zap.NewBuilder(zap.HeaderSize + clientObjectSize + len(payload))
	ob := b.StartObject(clientObjectSize)
	ob.SetUint8(clientFieldStatus, 0)
	if len(payload) > 0 {
		ob.SetBytes(clientFieldPayload, payload)
	}
	ob.FinishAsRoot()
	msg, err := zap.Parse(b.Finish())
	if err != nil {
		t.Fatalf("build client request: %v", err)
	}
	return msg
}

// A ZAP field offset is a BYTE offset and a bytes field is EIGHT bytes wide —
// SetBytes writes a uint32 pointer at the offset and a uint32 length at
// offset+4. The old layout spaced fields one byte apart, so each write ate the
// previous one. This asserts the arithmetic directly, because it is the fact
// that made the whole surface unreachable and it is invisible in a field name.
func TestBytesFieldIsEightBytesWide(t *testing.T) {
	if fieldPayload-fieldStatus < 8 {
		t.Fatalf("fieldStatus=%d and fieldPayload=%d are %d bytes apart; a bytes field needs 8 "+
			"(uint32 pointer + uint32 length), so the second write would corrupt the first",
			fieldStatus, fieldPayload, fieldPayload-fieldStatus)
	}
	if objectSize < fieldPayload+8 {
		t.Fatalf("objectSize=%d does not cover fieldPayload=%d plus its 8 bytes", objectSize, fieldPayload)
	}
}

// Two arguments survive each other. Under the old layout (orgID 8, walletID 9)
// this read back org_id "" with wallet_id intact, so zapKeygen refused every
// request any client could physically send.
func TestBothArgumentsSurviveTheRoundTrip(t *testing.T) {
	body, err := json.Marshal(zapArgs{OrgID: "acme", WalletID: "w_123"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := zapDecode(clientRequest(t, OpMPCKeygen, body))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OrgID != "acme" {
		t.Errorf("org_id = %q, want acme — the second field overwrote the first", got.OrgID)
	}
	if got.WalletID != "w_123" {
		t.Errorf("wallet_id = %q, want w_123", got.WalletID)
	}
}

// The reply this server writes must be readable by the client's parser. Under
// the old layout an 85-byte JSON body came back with '{' replaced by 0x00,
// because data's length word sat one byte past what the object reserved.
func TestReplyIsReadableByTheClient(t *testing.T) {
	payload := []byte(`{"wallet_id":"w_123","address":"0xabc","status":"ready"}`)
	reply, err := zapOK(payload)
	if err != nil {
		t.Fatalf("zapOK: %v", err)
	}

	root := reply.Root()
	if s := root.Uint8(clientFieldStatus); s != 0 {
		t.Fatalf("status = %d, want 0", s)
	}
	got := root.Bytes(clientFieldPayload)
	if string(got) != string(payload) {
		t.Fatalf("payload round-trip corrupted:\n got %q\nwant %q", got, payload)
	}
	// It must still parse as JSON — the old bug destroyed exactly one byte, the
	// opening brace, which a length check alone would not have caught.
	var out map[string]any
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("payload is not valid JSON after the round trip: %v", err)
	}
}

// An error travels in the same field as a success, distinguished by the status
// byte, so a caller reads one place.
func TestErrorTravelsInThePayloadField(t *testing.T) {
	reply, err := zapError("org_id and wallet_id required")
	if err != nil {
		t.Fatalf("zapError: %v", err)
	}
	root := reply.Root()
	if s := root.Uint8(clientFieldStatus); s != 1 {
		t.Fatalf("status = %d, want 1", s)
	}
	if msg := string(root.Bytes(clientFieldPayload)); msg != "org_id and wallet_id required" {
		t.Fatalf("error message = %q", msg)
	}
}

// A body that is not JSON is refused as such. Answering "org_id required" to a
// client sending the wrong frame sends them looking for a missing argument
// instead of a mismatched wire.
func TestWrongFrameIsRefusedAsAWireError(t *testing.T) {
	_, err := zapDecode(clientRequest(t, OpMPCKeygen, []byte("not json at all")))
	if err == nil {
		t.Fatal("a non-JSON body decoded cleanly")
	}
	if _, err := zapDecode(clientRequest(t, OpMPCKeygen, nil)); err == nil {
		t.Fatal("an empty body decoded cleanly")
	}
}
