package p2p

import (
	"testing"

	"fastpos/internal/chain"
)

func TestEnvelopeSignAndVerify(t *testing.T) {
	pub, priv, _, err := chain.DeterministicKeypair("p2p-test-validator")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}

	proposal := BlockProposal{
		Height:     10,
		PrevHash:   "abc",
		ProposerID: "v1",
		BlockHash:  "def",
		StateRoot:  "root",
		Timestamp:  1700000002000,
	}

	env, err := NewEnvelope(MessageTypeBlockProposal, "v1", proposal, priv)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	if err := VerifyEnvelope(env, pub, "v1"); err != nil {
		t.Fatalf("verify envelope: %v", err)
	}

	decoded, err := DecodePayload[BlockProposal](env)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded.BlockHash != proposal.BlockHash {
		t.Fatalf("decoded payload mismatch: got %s want %s", decoded.BlockHash, proposal.BlockHash)
	}
}

func TestEnvelopeTamperDetected(t *testing.T) {
	pub, priv, _, err := chain.DeterministicKeypair("p2p-test-validator-2")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}

	vote := BlockVote{
		Height:    10,
		BlockHash: "hash",
		VoterID:   "v2",
		Approve:   true,
		Timestamp: 1700000002100,
	}
	env, err := NewEnvelope(MessageTypeBlockVote, "v2", vote, priv)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}

	env.Payload = []byte(`{"height":10,"blockHash":"tampered","voterId":"v2","approve":true,"timestamp":1700000002100}`)
	if err := VerifyEnvelope(env, pub, "v2"); err == nil {
		t.Fatalf("expected signature verification failure for tampered payload")
	}
}
