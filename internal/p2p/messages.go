package p2p

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"fastpos/internal/chain"
)

const (
	MessageTypeBlockProposal = "block_proposal"
	MessageTypeBlockVote     = "block_vote"
	MessageTypeBlockFinalize = "block_finalize"
)

type Envelope struct {
	Type      string          `json:"type"`
	SenderID  string          `json:"senderId"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type BlockProposal struct {
	Block chain.Block `json:"block"`
}

type BlockVote struct {
	Height    uint64 `json:"height"`
	BlockHash string `json:"blockHash"`
	VoterID   string `json:"voterId"`
	Approve   bool   `json:"approve"`
	Timestamp int64  `json:"timestamp"`
}

type BlockFinalize struct {
	Block      chain.Block `json:"block"`
	YesStake   uint64      `json:"yesStake"`
	TotalStake uint64      `json:"totalStake"`
	Timestamp  int64       `json:"timestamp"`
}

func NewEnvelope(messageType, senderID string, payload any, privKeyHex string) (Envelope, error) {
	if messageType == "" {
		return Envelope{}, errors.New("message type is required")
	}
	if senderID == "" {
		return Envelope{}, errors.New("sender id is required")
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal payload: %w", err)
	}
	priv, err := parsePrivateKeyHex(privKeyHex)
	if err != nil {
		return Envelope{}, err
	}

	body := signingBytes(messageType, senderID, payloadBytes)
	sig := ed25519.Sign(priv, body)

	return Envelope{
		Type:      messageType,
		SenderID:  senderID,
		Payload:   payloadBytes,
		Signature: hex.EncodeToString(sig),
	}, nil
}

func VerifyEnvelope(env Envelope, senderPubKeyHex string, expectedSenderID string) error {
	if env.Type == "" {
		return errors.New("envelope type is required")
	}
	if env.SenderID == "" {
		return errors.New("envelope senderId is required")
	}
	if expectedSenderID != "" && env.SenderID != expectedSenderID {
		return fmt.Errorf("unexpected sender id: got %s want %s", env.SenderID, expectedSenderID)
	}
	if len(env.Payload) == 0 {
		return errors.New("envelope payload is required")
	}
	if env.Signature == "" {
		return errors.New("envelope signature is required")
	}

	pub, err := parsePublicKeyHex(senderPubKeyHex)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d", len(sig))
	}

	body := signingBytes(env.Type, env.SenderID, env.Payload)
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("invalid envelope signature")
	}

	return nil
}

func DecodePayload[T any](env Envelope) (T, error) {
	var out T
	if len(env.Payload) == 0 {
		return out, errors.New("empty payload")
	}
	if err := json.Unmarshal(env.Payload, &out); err != nil {
		return out, fmt.Errorf("decode payload: %w", err)
	}
	return out, nil
}

func signingBytes(messageType, senderID string, payload []byte) []byte {
	b := make([]byte, 0, len(messageType)+len(senderID)+len(payload)+2)
	b = append(b, []byte(messageType)...)
	b = append(b, '|')
	b = append(b, []byte(senderID)...)
	b = append(b, '|')
	b = append(b, payload...)
	return b
}

func parsePrivateKeyHex(privKeyHex string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("invalid private key length: got %d", len(raw))
}

func parsePublicKeyHex(pubKeyHex string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
