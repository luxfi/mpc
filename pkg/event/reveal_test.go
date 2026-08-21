package event

import (
	"strings"
	"testing"
)

// The consensus transport delivers by exact map lookup on the topic string. It
// has no wildcards, so a party subscribed to a pattern is subscribed to nothing
// and hears no request — the opening then times out with every share present
// and nobody having been asked, which reads like a quorum problem and is not
// one. That is how this shipped, and a "*" here is the whole of it.
func TestTopicsAreLiteral(t *testing.T) {
	for name, topic := range map[string]string{
		"RevealRequestTopic":    RevealRequestTopic,
		"RevealAnswerTopicBase": RevealAnswerTopicBase,
	} {
		if strings.ContainsAny(topic, "*>") {
			t.Errorf("%s = %q carries a wildcard; this transport matches exactly", name, topic)
		}
	}
}

// One request reaches every party, so both sides have to name the same string.
// The session that separates two openings in flight rides in the body, and the
// answers come back on their own per-session topic built from the base.
func TestARequestIsOneTopicAndAnAnswerIsPerSession(t *testing.T) {
	if RevealRequestTopic != "mpc.reveal_request" {
		t.Errorf("request topic = %q", RevealRequestTopic)
	}
	if RevealAnswerTopicBase != "mpc.reveal_answer" {
		t.Errorf("answer base = %q", RevealAnswerTopicBase)
	}
	if strings.HasPrefix(RevealAnswerTopicBase, RevealRequestTopic) {
		t.Error("the answer base is a prefix of the request topic; a request would land on the answer path")
	}
	var r RevealRequest
	if _, ok := any(r.SessionID).(string); !ok {
		t.Error("the request must carry its session, since the topic no longer does")
	}
}
