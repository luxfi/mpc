// Copyright (c) 2024-2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Threshold-FHE wallet sessions: a dealerless key generation across the ready
// committee, then encryption and threshold decryption.
//
// Each node samples only its own secret contribution, broadcasts the public
// collective-key share and unicasts one Shamir sub-share per peer; summing the
// sub-shares it receives gives it a share of a collective secret no node and no
// message ever carries.

package mpc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/multiparty"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/tfhe"

	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/utils"
)

// tfheParams resolves the parameter set every threshold-FHE wallet uses:
// ~128-bit security at N=1024.
func tfheParams() (fhe.Parameters, fhe.ParametersLiteral, error) {
	lit := fhe.PN10QP27
	params, err := fhe.NewParametersFromLiteral(lit)
	return params, lit, err
}

// TFHESession is the committee side of a threshold-FHE wallet: encrypt under
// the collective public key, contribute one partial decryption, collect the
// peers' and combine. No method returns a key; no node holds one.
type TFHESession interface {
	Session

	// Encrypt encrypts value under the collective public key.
	Encrypt(value uint64, fheType fhe.FheUintType) ([]byte, error)

	// PartialDecrypt contributes this node's partial decryption and broadcasts
	// it to the committee.
	PartialDecrypt(ciphertext []byte) (tfhe.Decryption, error)

	// AddShare records a peer's partial decryption.
	AddShare(contribution tfhe.Decryption) error

	// CanDecrypt reports whether the threshold has been met for ciphertext.
	CanDecrypt(ciphertext []byte) bool

	// Decrypt combines the collected partial decryptions of ciphertext.
	Decrypt(ciphertext []byte) (uint64, error)
}

var (
	_ Session     = (*tfheKeygenSession)(nil)
	_ TFHESession = (*tfheComputeSession)(nil)
)

// Round-1 messages. Neither can carry a secret key: one is a public
// collective-key share, the other one Shamir point addressed to one recipient.

// tfhePublicShare is broadcast: the sender's share -a·s_j + e_j of the
// collective public key.
type tfhePublicShare struct {
	From  int    `json:"from"`
	Share []byte `json:"share"`
}

// tfheSubShare is unicast: the coefficientwise Shamir evaluation, at the
// recipient's position, of the sender's own contribution.
type tfheSubShare struct {
	From   int      `json:"from"`
	To     int      `json:"to"`
	Coeffs []uint64 `json:"coeffs"`
}

// tfheCRSSeed derives the ceremony's common reference seed from the wallet and
// the committee in canonical order. The polynomial it seeds is public, and
// every node must derive the same seed or the public keys disagree.
func tfheCRSSeed(walletID string, ids []party.ID) []byte {
	h := sha256.New()
	h.Write([]byte("LUX/MPC/TFHE/DKG/CRS/v1"))
	h.Write([]byte(walletID))
	for _, id := range ids {
		h.Write([]byte{0})
		h.Write([]byte(id))
	}
	return h.Sum(nil)
}

// tfhePositions assigns each member its 1-based Shamir position from the
// canonical order of the party IDs, identically on every node.
func tfhePositions(ids []party.ID) ([]party.ID, map[party.ID]int) {
	ordered := make([]party.ID, len(ids))
	copy(ordered, ids)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	at := make(map[party.ID]int, len(ordered))
	for i, id := range ordered {
		at[id] = i + 1
	}
	return ordered, at
}

// tfhePositionsByNode indexes committee positions by node ID, the identity an
// inbound message authenticates as its sender.
func tfhePositionsByNode(ordered []party.ID) map[string]int {
	at := make(map[string]int, len(ordered))
	for i, id := range ordered {
		at[extractNodeID(string(id))] = i + 1
	}
	return at
}

// ============================================================================
// Key generation.
// ============================================================================

// tfheKeygenSession runs one dealerless key-generation ceremony.
type tfheKeygenSession struct {
	session

	params    fhe.Parameters
	paramsLit fhe.ParametersLiteral
	total     int
	position  int
	// byNode maps an authenticated sender to the position it may speak for.
	byNode map[string]int

	ckg multiparty.PublicKeyGenProtocol
	crp multiparty.PublicKeyGenCRP

	mu sync.Mutex
	// dealer holds this node's own secret contribution, zeroized as soon as
	// the node holds its share.
	dealer *tfhe.Party
	public map[int]multiparty.PublicKeyGenShare
	sub    map[int]tfhe.Point
	done   bool
}

func newTFHEKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	params fhe.Parameters,
	paramsLit fhe.ParametersLiteral,
	kv kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	orgID string,
) (*tfheKeygenSession, error) {
	ordered, positions := tfhePositions(partyIDs)
	position, ok := positions[selfPartyID]
	if !ok {
		return nil, fmt.Errorf("mpc/tfhe: this node is not in the committee for %s", walletID)
	}
	total := len(ordered)
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("mpc/tfhe: threshold %d out of range for committee of %d", threshold, total)
	}

	crp, ckg, err := tfhe.Reference(params, tfheCRSSeed(walletID, ordered))
	if err != nil {
		return nil, fmt.Errorf("mpc/tfhe: common reference: %w", err)
	}
	dealer, err := tfhe.NewParty(position, threshold, total, params)
	if err != nil {
		return nil, fmt.Errorf("mpc/tfhe: committee member %d: %w", position, err)
	}

	return &tfheKeygenSession{
		session: session{
			walletID:           walletID,
			orgID:              orgID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           ordered,
			subscriberList:     []messaging.Subscription{},
			rounds:             2,
			outCh:              make(chan msg, 2*total+2),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          threshold,
			kvstore:            kv,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         newDedupMap(),
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("tfhe:keygen:broadcast:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("tfhe:keygen:direct:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		params:    params,
		paramsLit: paramsLit,
		total:     total,
		position:  position,
		byNode:    tfhePositionsByNode(ordered),
		ckg:       ckg,
		crp:       crp,
		dealer:    dealer,
		public:    make(map[int]multiparty.PublicKeyGenShare, total),
		sub:       make(map[int]tfhe.Point, total),
	}, nil
}

// ListenToIncomingMessageAsync routes the broadcast topic to collective-key
// shares and the direct topic to sub-shares.
func (s *tfheKeygenSession) ListenToIncomingMessageAsync() {
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.onInbound(m.Data, s.acceptPublicShare)
	})
	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to %s", broadcastTopic)
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, broadcastSub)

	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.onInbound(m.Data, s.acceptSubShare)
	})
	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to %s", directTopic)
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Int("position", s.position).
		Msg("Listening for threshold-FHE key-generation messages")
}

// onInbound authenticates a wire message, resolves the sender to the position
// it may speak for, de-duplicates, and dispatches the body. The position comes
// from the sender, never from the body.
func (s *tfheKeygenSession) onInbound(raw []byte, accept func(from int, body []byte) error) {
	m := &types.Message{}
	if err := json.Unmarshal(raw, m); err != nil {
		s.logger.Error().Err(err).Msg("Malformed threshold-FHE message")
		return
	}
	if err := s.verifyInboundSignature(m); err != nil {
		s.logger.Warn().Err(err).Str("sender", m.SenderNodeID).Msg("Dropping message with invalid signature")
		return
	}
	from, ok := s.byNode[m.SenderNodeID]
	if !ok {
		s.logger.Warn().Str("sender", m.SenderNodeID).Msg("Dropping message from a node outside the committee")
		return
	}
	if s.processing.seen(fmt.Sprintf("%x", utils.GetMessageHash(m.Body))) {
		return
	}
	if err := accept(from, m.Body); err != nil {
		s.logger.Warn().Err(err).Str("sender", m.SenderNodeID).Msg("Rejecting threshold-FHE message")
	}
}

// ProcessInboundMessage satisfies the base session contract. Key generation
// routes per topic, so a message reaching here is unattributable.
func (s *tfheKeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.logger.Error().
		Int("msgLen", len(msgBytes)).
		Msg("Threshold-FHE key generation received an untopiced message; discarded")
}

func (s *tfheKeygenSession) acceptPublicShare(from int, body []byte) error {
	var wire tfhePublicShare
	if err := json.Unmarshal(body, &wire); err != nil {
		return fmt.Errorf("decode collective-key share: %w", err)
	}
	if wire.From != from {
		return fmt.Errorf("position %d sent a collective-key share claiming position %d", from, wire.From)
	}
	if len(wire.Share) == 0 {
		return fmt.Errorf("collective-key share from position %d is empty", wire.From)
	}
	share := s.ckg.AllocateShare()
	if err := share.UnmarshalBinary(wire.Share); err != nil {
		return fmt.Errorf("decode collective-key share from position %d: %w", wire.From, err)
	}

	s.mu.Lock()
	if _, dup := s.public[wire.From]; dup {
		s.mu.Unlock()
		return fmt.Errorf("position %d sent two collective-key shares", wire.From)
	}
	s.public[wire.From] = share
	s.mu.Unlock()

	s.finalizeIfComplete()
	return nil
}

func (s *tfheKeygenSession) acceptSubShare(from int, body []byte) error {
	var wire tfheSubShare
	if err := json.Unmarshal(body, &wire); err != nil {
		return fmt.Errorf("decode sub-share: %w", err)
	}
	if wire.From != from {
		return fmt.Errorf("position %d sent a sub-share claiming position %d", from, wire.From)
	}
	if wire.To != s.position {
		return fmt.Errorf("sub-share addressed to position %d delivered to %d", wire.To, s.position)
	}
	if n := s.params.ParamsLWE().RingQ().N(); len(wire.Coeffs) != n {
		return fmt.Errorf("sub-share from position %d has %d coefficients, want %d", wire.From, len(wire.Coeffs), n)
	}

	s.mu.Lock()
	if _, dup := s.sub[wire.From]; dup {
		s.mu.Unlock()
		return fmt.Errorf("position %d sent two sub-shares", wire.From)
	}
	s.sub[wire.From] = tfhe.Point{From: wire.From, To: wire.To, Coeffs: wire.Coeffs}
	s.mu.Unlock()

	s.finalizeIfComplete()
	return nil
}

// Init deals this node's round-1 contribution: one broadcast public share and
// one unicast sub-share per peer, its own folded in locally.
func (s *tfheKeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Int("committee", s.total).
		Int("position", s.position).
		Msg("Dealing threshold-FHE key generation")

	s.mu.Lock()
	dealer := s.dealer
	s.mu.Unlock()
	if dealer == nil {
		s.errCh <- fmt.Errorf("mpc/tfhe: committee member already finalized")
		return
	}

	publicShare, subShares, err := dealer.Deal(s.crp)
	if err != nil {
		s.errCh <- fmt.Errorf("mpc/tfhe: deal: %w", err)
		return
	}

	shareBytes, err := publicShare.Share.MarshalBinary()
	if err != nil {
		s.errCh <- fmt.Errorf("mpc/tfhe: encode collective-key share: %w", err)
		return
	}
	broadcast, err := json.Marshal(tfhePublicShare{From: s.position, Share: shareBytes})
	if err != nil {
		s.errCh <- fmt.Errorf("mpc/tfhe: encode broadcast: %w", err)
		return
	}

	s.mu.Lock()
	s.public[s.position] = publicShare.Share
	for _, sub := range subShares {
		if sub.To == s.position {
			s.sub[sub.From] = sub
		}
	}
	s.mu.Unlock()

	s.outCh <- msg{FromPartyID: s.selfPartyID, IsBroadcast: true, Data: broadcast}

	for _, sub := range subShares {
		if sub.To == s.position {
			continue
		}
		recipient := s.partyIDs[sub.To-1]
		body, err := json.Marshal(tfheSubShare{From: sub.From, To: sub.To, Coeffs: sub.Coeffs})
		if err != nil {
			s.errCh <- fmt.Errorf("mpc/tfhe: encode sub-share for position %d: %w", sub.To, err)
			return
		}
		s.outCh <- msg{FromPartyID: s.selfPartyID, ToPartyIDs: []party.ID{recipient}, Data: body}
	}

	s.finalizeIfComplete()
}

// finalizeIfComplete assembles the collective public key and this node's
// share once every member's round-1 output has arrived, then erases the
// contribution.
func (s *tfheKeygenSession) finalizeIfComplete() {
	s.mu.Lock()
	if s.done || len(s.public) != s.total || len(s.sub) != s.total {
		s.mu.Unlock()
		return
	}
	s.done = true
	dealer := s.dealer
	publicShares := make([]tfhe.Public, 0, s.total)
	for from, share := range s.public {
		publicShares = append(publicShares, tfhe.Public{From: from, Share: share})
	}
	inbound := make([]tfhe.Point, 0, s.total)
	for _, sub := range s.sub {
		inbound = append(inbound, sub)
	}
	s.mu.Unlock()

	sort.Slice(publicShares, func(i, j int) bool { return publicShares[i].From < publicShares[j].From })
	sort.Slice(inbound, func(i, j int) bool { return inbound[i].From < inbound[j].From })

	pub, err := tfhe.Assemble(s.ckg, s.crp, publicShares, s.params)
	if err != nil {
		s.errCh <- fmt.Errorf("mpc/tfhe: collective public key: %w", err)
		return
	}
	share, err := dealer.Aggregate(inbound)
	if err != nil {
		s.errCh <- fmt.Errorf("mpc/tfhe: fold sub-shares: %w", err)
		return
	}

	// The node keeps only its share from here.
	dealer.Zeroize()
	s.mu.Lock()
	s.dealer = nil
	s.mu.Unlock()

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		s.errCh <- fmt.Errorf("mpc/tfhe: encode collective public key: %w", err)
		return
	}
	member := &tfhe.Member{
		Params:    s.paramsLit,
		Threshold: s.threshold,
		Total:     s.total,
		Key:       pubBytes,
		Share:     share,
	}
	if err := member.Validate(); err != nil {
		s.errCh <- err
		return
	}
	if err := s.persist(member); err != nil {
		s.errCh <- err
		return
	}
	s.finishCh <- true
}

func (s *tfheKeygenSession) persist(member *tfhe.Member) error {
	body, err := tfhe.Marshal(member)
	if err != nil {
		return fmt.Errorf("mpc/tfhe: encode committee member: %w", err)
	}
	key := OrgScopedKey(s.orgID, tfheWalletKey(s.walletID))
	if err := s.kvstore.Put(key, body); err != nil {
		return fmt.Errorf("mpc/tfhe: store committee member for %s: %w", s.walletID, err)
	}
	info := &keyinfo.KeyInfo{
		ParticipantPeerIDs: convertFromPartyIDs(s.partyIDs),
		Threshold:          s.threshold,
		Version:            1,
	}
	if err := s.keyinfoStore.Save(key, info); err != nil {
		return fmt.Errorf("mpc/tfhe: store key info for %s: %w", s.walletID, err)
	}
	return nil
}

// tfheWalletKey is the key-store name for a threshold-FHE wallet.
func tfheWalletKey(walletID string) string { return fmt.Sprintf("tfhe:%s", walletID) }

func (s *tfheKeygenSession) ProcessOutboundMessage() {
	deadline := time.After(KeygenTimeout)
	for {
		select {
		case m, ok := <-s.outCh:
			if !ok {
				return
			}
			recipients := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipients[i] = string(pid)
			}
			s.sendMsg(&types.Message{
				SessionID:    s.walletID,
				SenderID:     string(m.FromPartyID),
				RecipientIDs: recipients,
				Body:         m.Data,
				IsBroadcast:  m.IsBroadcast,
			})

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("Threshold-FHE key generation failed")
			s.externalFinishChan <- ""
			return

		case <-s.finishCh:
			s.logger.Info().
				Str("walletID", s.walletID).
				Int("threshold", s.threshold).
				Int("committee", s.total).
				Msg("Threshold-FHE key generation complete")
			s.externalFinishChan <- OrgScopedKey(s.orgID, tfheWalletKey(s.walletID))
			return

		case <-deadline:
			collective, sub := s.progress()
			s.logger.Error().
				Dur("timeout", KeygenTimeout).
				Int("collectiveShares", collective).
				Int("subShares", sub).
				Msg("Threshold-FHE key generation timed out")
			s.externalFinishChan <- ""
			return
		}
	}
}

// progress reports how much of round 1 has arrived.
func (s *tfheKeygenSession) progress() (collective, sub int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.public), len(s.sub)
}

func (s *tfheKeygenSession) Stop() {
	s.unsubscribe()
	s.processing.stop()
	s.mu.Lock()
	if s.dealer != nil {
		s.dealer.Zeroize()
		s.dealer = nil
	}
	s.mu.Unlock()
}

func (s *tfheKeygenSession) WaitForFinish() string { return <-s.externalFinishChan }

// ============================================================================
// Encryption and threshold decryption.
// ============================================================================

// tfheComputeSession is one node's part in encrypting and threshold-decrypting
// a committee ciphertext.
type tfheComputeSession struct {
	session

	member *tfhe.Member
	params fhe.Parameters
	pub    *fhe.PublicKey
	// byNode maps an authenticated sender to the position it may speak for,
	// from the roster recorded at key generation.
	byNode map[string]int

	mu sync.Mutex
	// collected holds every partial decryption seen, keyed first by the
	// ciphertext it is bound to and then by the contributing member.
	collected map[[32]byte]map[int]tfhe.Decryption
}

func newTFHEComputeSession(
	sessionID string,
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	participantIDs []party.ID,
	kv kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	orgID string,
) (*tfheComputeSession, error) {
	stored, err := GetKeyShareWithFallback(kv, orgID, tfheWalletKey(walletID))
	if err != nil {
		return nil, fmt.Errorf("mpc/tfhe: load committee member for %s: %w", walletID, err)
	}
	member, err := tfhe.Unmarshal(stored)
	if err != nil {
		return nil, err
	}
	params, err := member.Parameters()
	if err != nil {
		return nil, err
	}
	pub, err := member.Collective()
	if err != nil {
		return nil, err
	}

	// Positions come from the roster the ceremony recorded, not from the
	// caller's participant list, which would renumber a partial committee.
	info, err := keyinfoStore.Get(OrgScopedKey(orgID, tfheWalletKey(walletID)))
	if err != nil {
		return nil, fmt.Errorf("mpc/tfhe: load committee roster for %s: %w", walletID, err)
	}
	if len(info.ParticipantPeerIDs) != member.Total {
		return nil, fmt.Errorf("mpc/tfhe: committee roster for %s has %d members, share says %d",
			walletID, len(info.ParticipantPeerIDs), member.Total)
	}
	roster := make([]party.ID, len(info.ParticipantPeerIDs))
	for i, id := range info.ParticipantPeerIDs {
		roster[i] = party.ID(id)
	}
	ordered, _ := tfhePositions(roster)

	return &tfheComputeSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			orgID:              orgID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           ordered,
			subscriberList:     []messaging.Subscription{},
			rounds:             1,
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          member.Threshold,
			kvstore:            kv,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         newDedupMap(),
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("tfhe:compute:broadcast:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("tfhe:compute:direct:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		member:    member,
		params:    params,
		pub:       pub,
		byNode:    tfhePositionsByNode(ordered),
		collected: make(map[[32]byte]map[int]tfhe.Decryption),
	}, nil
}

func (s *tfheComputeSession) ListenToIncomingMessageAsync() {
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, broadcastSub)

	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, directSub)
}

func (s *tfheComputeSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Int("threshold", s.member.Threshold).
		Int("position", s.member.Share.Index).
		Msg("Threshold-FHE decryption session ready")
}

func (s *tfheComputeSession) ProcessInboundMessage(msgBytes []byte) {
	m := &types.Message{}
	if err := json.Unmarshal(msgBytes, m); err != nil {
		s.logger.Error().Err(err).Msg("Malformed threshold-FHE decryption message")
		return
	}
	if err := s.verifyInboundSignature(m); err != nil {
		s.logger.Warn().Err(err).Str("sender", m.SenderNodeID).Msg("Dropping message with invalid signature")
		return
	}
	from, ok := s.byNode[m.SenderNodeID]
	if !ok {
		s.logger.Warn().Str("sender", m.SenderNodeID).Msg("Dropping partial decryption from a node outside the committee")
		return
	}
	if s.processing.seen(fmt.Sprintf("%x", utils.GetMessageHash(m.Body))) {
		return
	}
	var contribution tfhe.Decryption
	if err := json.Unmarshal(m.Body, &contribution); err != nil {
		s.logger.Error().Err(err).Msg("Malformed partial decryption")
		return
	}
	if contribution.From != from {
		s.logger.Warn().
			Str("sender", m.SenderNodeID).
			Int("claimed", contribution.From).
			Int("actual", from).
			Msg("Dropping partial decryption that claims another member's position")
		return
	}
	if err := s.AddShare(contribution); err != nil {
		s.logger.Warn().Err(err).Str("sender", m.SenderNodeID).Msg("Rejecting partial decryption")
	}
}

func (s *tfheComputeSession) ProcessOutboundMessage() {
	for {
		select {
		case m, ok := <-s.outCh:
			if !ok {
				return
			}
			recipients := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipients[i] = string(pid)
			}
			s.sendMsg(&types.Message{
				SessionID:    s.sessionID,
				SenderID:     string(m.FromPartyID),
				RecipientIDs: recipients,
				Body:         m.Data,
				IsBroadcast:  m.IsBroadcast,
			})

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("Threshold-FHE decryption error")

		case <-s.finishCh:
			return
		}
	}
}

func (s *tfheComputeSession) Stop() {
	s.unsubscribe()
	s.processing.stop()
}

func (s *tfheComputeSession) WaitForFinish() string { return <-s.externalFinishChan }

// Encrypt encrypts value under the committee's collective public key.
func (s *tfheComputeSession) Encrypt(value uint64, fheType fhe.FheUintType) ([]byte, error) {
	return tfhe.Encrypt(s.params, s.pub, value, fheType)
}

// PartialDecrypt computes this node's contribution, records it, and broadcasts
// it to the committee.
func (s *tfheComputeSession) PartialDecrypt(ciphertext []byte) (tfhe.Decryption, error) {
	contribution, err := s.member.Decrypt(ciphertext, nil)
	if err != nil {
		return tfhe.Decryption{}, err
	}
	if err := s.AddShare(contribution); err != nil {
		return tfhe.Decryption{}, err
	}
	body, err := json.Marshal(contribution)
	if err != nil {
		return tfhe.Decryption{}, fmt.Errorf("mpc/tfhe: encode partial decryption: %w", err)
	}
	s.outCh <- msg{FromPartyID: s.selfPartyID, IsBroadcast: true, Data: body}
	return contribution, nil
}

// AddShare records a partial decryption, keyed by the ciphertext it is bound
// to and by the member. A second from the same member is refused.
func (s *tfheComputeSession) AddShare(contribution tfhe.Decryption) error {
	if contribution.From < 1 || contribution.From > s.member.Total {
		return fmt.Errorf("mpc/tfhe: partial decryption from position %d outside [1,%d]",
			contribution.From, s.member.Total)
	}
	if len(contribution.Partials) == 0 {
		return fmt.Errorf("mpc/tfhe: partial decryption from position %d is empty", contribution.From)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byMember, ok := s.collected[contribution.Digest]
	if !ok {
		byMember = make(map[int]tfhe.Decryption, s.member.Total)
		s.collected[contribution.Digest] = byMember
	}
	if _, dup := byMember[contribution.From]; dup {
		return fmt.Errorf("mpc/tfhe: position %d already contributed to this ciphertext", contribution.From)
	}
	byMember[contribution.From] = contribution
	return nil
}

// CanDecrypt reports whether the threshold has been met for ciphertext.
func (s *tfheComputeSession) CanDecrypt(ciphertext []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.collected[tfhe.Digest(ciphertext)]) >= s.member.Threshold
}

// Decrypt combines the collected partial decryptions, failing rather than
// returning a value when no quorum recombines.
func (s *tfheComputeSession) Decrypt(ciphertext []byte) (uint64, error) {
	digest := tfhe.Digest(ciphertext)
	s.mu.Lock()
	from := make([]tfhe.Decryption, 0, len(s.collected[digest]))
	for _, contribution := range s.collected[digest] {
		from = append(from, contribution)
	}
	s.mu.Unlock()

	bits, err := tfhe.Decrypt(ciphertext, from, s.params, s.member.Threshold)
	if err != nil {
		return 0, err
	}
	return tfhe.Value(bits), nil
}
