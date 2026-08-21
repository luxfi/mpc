package event

// Opening a secret sealed to a wallet's share set.
//
// Signing is a protocol: rounds, state, every party waiting on the others.
// Opening is not. Each party computes its answer from its own share and the
// ciphertext alone, so this is a fan-out and a fan-in with nothing in between —
// no session to build, no round to sequence, no party that must wait to speak.
//
// That is why these are their own topics rather than another message on the
// signing stream: a request that needs no session should not be routed through
// the machinery that keeps them.
const (
	RevealPublisherStream = "mpc-reveal"
	RevealConsumerStream  = "mpc-reveal-consumer"

	// RevealRequestTopic is what every party listens to. One request reaches
	// them all and each answers independently.
	//
	// One literal topic, not a pattern. The consensus transport delivers by
	// exact map lookup — it has no wildcards — so a party subscribed to
	// "mpc.reveal_request.*" hears a request published under
	// "mpc.reveal_request.<session>" never, and the opening times out with
	// every share present and nobody having been asked. The session travels in
	// the request body, where a reader needs it anyway.
	RevealRequestTopic = "mpc.reveal_request"

	// RevealAnswerTopic carries the answers back, one topic per session, so two
	// openings in flight cannot be combined into one. Both sides build the same
	// literal from the same base, so no pattern is involved here either.
	RevealAnswerTopicBase = "mpc.reveal_answer"
)

// RevealRequest asks the share set behind KeyID to open Ciphertext.
//
// It carries no threshold and no party list. Both are properties of the share
// set, which every party already holds and the combiner reads from the same
// place — a request that could name its own threshold could name one.
type RevealRequest struct {
	SessionID  string `json:"session_id"`
	OrgID      string `json:"org_id"`
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
}

// RevealAnswer is one party's contribution, or its reason for having none.
//
// A party that cannot answer says so rather than staying silent, because the
// difference between "this node holds no share for that key" and "this node is
// gone" is the difference between a request that will never succeed and one
// worth waiting out.
type RevealAnswer struct {
	SessionID string `json:"session_id"`
	PartyID   string `json:"party_id"`
	Answer    []byte `json:"answer,omitempty"`
	Error     string `json:"error,omitempty"`
}
