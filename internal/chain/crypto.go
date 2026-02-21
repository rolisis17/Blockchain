package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

func AddressFromPubKey(pub []byte) Address {
	sum := sha256.Sum256(pub)
	return Address(hex.EncodeToString(sum[:20]))
}

func AddressFromPubKeyHex(pubHex string) (Address, error) {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return "", fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid pubkey length: got %d", len(pub))
	}
	return AddressFromPubKey(pub), nil
}

func GenerateKeypair() (pubHex string, privHex string, address Address, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate keypair: %w", err)
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), AddressFromPubKey(pub), nil
}

func DeterministicKeypair(label string) (pubHex string, privHex string, address Address, err error) {
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), hex.EncodeToString(priv), AddressFromPubKey(pub), nil
}

func SignTransaction(tx *Transaction, privHex string) error {
	if tx == nil {
		return errors.New("nil transaction")
	}
	priv, pub, err := parsePrivateKey(privHex)
	if err != nil {
		return err
	}
	pubHex := hex.EncodeToString(pub)
	from := AddressFromPubKey(pub)

	if tx.From == "" {
		tx.From = from
	}
	if tx.From != from {
		return errors.New("transaction from does not match private key")
	}
	if tx.Timestamp == 0 {
		tx.Timestamp = time.Now().UnixMilli()
	}
	tx.PubKey = pubHex
	sig := ed25519.Sign(priv, tx.signingBytes())
	tx.Signature = hex.EncodeToString(sig)
	return nil
}

func PublicAndAddressFromPrivateKeyHex(privHex string) (pubHex string, address Address, err error) {
	_, pub, err := parsePrivateKey(privHex)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), AddressFromPubKey(pub), nil
}

func VerifyTransactionSignature(tx Transaction) error {
	if tx.PubKey == "" || tx.Signature == "" {
		return errors.New("missing pubkey or signature")
	}
	pubRaw, err := hex.DecodeString(tx.PubKey)
	if err != nil {
		return fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey length: got %d", len(pubRaw))
	}
	sigRaw, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sigRaw) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d", len(sigRaw))
	}

	expected := AddressFromPubKey(pubRaw)
	if tx.From != expected {
		return errors.New("from does not match pubkey")
	}

	if !ed25519.Verify(ed25519.PublicKey(pubRaw), tx.signingBytes(), sigRaw) {
		return errors.New("invalid signature")
	}
	return nil
}

func parsePrivateKey(privHex string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privRaw, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode private key: %w", err)
	}
	var priv ed25519.PrivateKey
	switch len(privRaw) {
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(privRaw)
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(privRaw)
	default:
		return nil, nil, fmt.Errorf("invalid private key length: got %d", len(privRaw))
	}
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}
