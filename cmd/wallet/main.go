package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"fastpos/internal/chain"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen":
		runGen()
	case "sign":
		runSign(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func runGen() {
	pub, priv, address, err := chain.GenerateKeypair()
	if err != nil {
		log.Fatalf("generate wallet: %v", err)
	}
	printJSON(map[string]string{
		"address":    string(address),
		"pubKey":     pub,
		"privateKey": priv,
	})
}

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	privateKey := fs.String("priv", "", "hex private key")
	kind := fs.String("kind", chain.TxKindTransfer, "transaction kind")
	to := fs.String("to", "", "recipient address")
	amount := fs.Uint64("amount", 0, "amount to transfer")
	fee := fs.Uint64("fee", 1, "transaction fee")
	nonce := fs.Uint64("nonce", 0, "sender nonce (required)")
	timestamp := fs.Int64("timestamp", 0, "unix ms timestamp (optional)")
	validatorID := fs.String("validator-id", "", "validator id for validator lifecycle txs")
	basisPoints := fs.Uint64("basis-points", 0, "slash basis points (1..10000) for validator_slash tx")
	_ = fs.Parse(args)

	if *privateKey == "" || *nonce == 0 {
		fs.Usage()
		os.Exit(1)
	}
	if err := validateSignArgs(*kind, *to, *validatorID, *amount, *basisPoints); err != nil {
		fmt.Fprintf(os.Stderr, "invalid sign args: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	tx := chain.Transaction{
		Kind:        *kind,
		To:          chain.Address(*to),
		Amount:      *amount,
		Fee:         *fee,
		Nonce:       *nonce,
		Timestamp:   *timestamp,
		ValidatorID: *validatorID,
		BasisPoints: *basisPoints,
	}
	if err := chain.SignTransaction(&tx, *privateKey); err != nil {
		log.Fatalf("sign tx: %v", err)
	}
	printJSON(tx)
}

func validateSignArgs(kind, to, validatorID string, amount, basisPoints uint64) error {
	switch kind {
	case "", chain.TxKindTransfer:
		if to == "" {
			return fmt.Errorf("--to is required for %q tx", chain.TxKindTransfer)
		}
		if amount == 0 {
			return fmt.Errorf("--amount must be > 0 for %q tx", chain.TxKindTransfer)
		}
		return nil
	case chain.TxKindValidatorBond, chain.TxKindValidatorUnbond:
		if validatorID == "" {
			return fmt.Errorf("--validator-id is required for %q tx", kind)
		}
		if amount == 0 {
			return fmt.Errorf("--amount must be > 0 for %q tx", kind)
		}
		return nil
	case chain.TxKindValidatorSlash:
		if validatorID == "" {
			return fmt.Errorf("--validator-id is required for %q tx", chain.TxKindValidatorSlash)
		}
		if basisPoints == 0 || basisPoints > 10_000 {
			return fmt.Errorf("--basis-points must be in [1,10000] for %q tx", chain.TxKindValidatorSlash)
		}
		if amount != 0 {
			return fmt.Errorf("--amount must be 0 for %q tx", chain.TxKindValidatorSlash)
		}
		return nil
	case chain.TxKindValidatorJail:
		if validatorID == "" {
			return fmt.Errorf("--validator-id is required for %q tx", chain.TxKindValidatorJail)
		}
		if amount != 0 {
			return fmt.Errorf("--amount must be 0 for %q tx", chain.TxKindValidatorJail)
		}
		if basisPoints != 0 {
			return fmt.Errorf("--basis-points must be 0 for %q tx", chain.TxKindValidatorJail)
		}
		return nil
	case chain.TxKindValidatorUnjail:
		if validatorID == "" {
			return fmt.Errorf("--validator-id is required for %q tx", chain.TxKindValidatorUnjail)
		}
		if amount != 0 {
			return fmt.Errorf("--amount must be 0 for %q tx", chain.TxKindValidatorUnjail)
		}
		if basisPoints != 0 {
			return fmt.Errorf("--basis-points must be 0 for %q tx", chain.TxKindValidatorUnjail)
		}
		return nil
	case chain.TxKindDelegate, chain.TxKindUndelegate:
		if validatorID == "" {
			return fmt.Errorf("--validator-id is required for %q tx", kind)
		}
		if amount == 0 {
			return fmt.Errorf("--amount must be > 0 for %q tx", kind)
		}
		if basisPoints != 0 {
			return fmt.Errorf("--basis-points must be 0 for %q tx", kind)
		}
		return nil
	case chain.TxKindProductSettle:
		if to == "" {
			return fmt.Errorf("--to is required for %q tx (product reference)", kind)
		}
		if amount == 0 {
			return fmt.Errorf("--amount must be > 0 for %q tx", kind)
		}
		if basisPoints != 0 {
			return fmt.Errorf("--basis-points must be 0 for %q tx", kind)
		}
		return nil
	case chain.TxKindProductAttest:
		if to == "" {
			return fmt.Errorf("--to is required for %q tx (proof reference)", kind)
		}
		if validatorID == "" {
			return fmt.Errorf("--validator-id is required for %q tx", kind)
		}
		if amount == 0 {
			return fmt.Errorf("--amount must be > 0 for %q tx", kind)
		}
		if basisPoints == 0 || basisPoints > 10_000 {
			return fmt.Errorf("--basis-points must be in [1,10000] for %q tx", kind)
		}
		return nil
	case chain.TxKindProductChallenge:
		if to == "" {
			return fmt.Errorf("--to is required for %q tx (proof id)", kind)
		}
		if amount == 0 {
			return fmt.Errorf("--amount must be > 0 for %q tx", kind)
		}
		if basisPoints != 0 {
			return fmt.Errorf("--basis-points must be 0 for %q tx", kind)
		}
		return nil
	case chain.TxKindProductResolveChallenge:
		if to == "" {
			return fmt.Errorf("--to is required for %q tx (challenge id)", kind)
		}
		if basisPoints > 10_000 {
			return fmt.Errorf("--basis-points must be in [0,10000] for %q tx", kind)
		}
		return nil
	default:
		return fmt.Errorf("unsupported --kind %q", kind)
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encode json: %v", err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  wallet gen")
	fmt.Fprintln(os.Stderr, "  wallet sign --priv <hex> --nonce <n> [--fee <n>] [--kind transfer|validator_bond|validator_unbond|validator_slash|validator_jail|validator_unjail|delegation_delegate|delegation_undelegate|product_settle|product_attest|product_challenge|product_resolve_challenge] ...")
	fmt.Fprintln(os.Stderr, "  transfer example: wallet sign --priv <hex> --kind transfer --to <addr> --amount 10 --fee 1 --nonce 1")
	fmt.Fprintln(os.Stderr, "  bond example: wallet sign --priv <hex> --kind validator_bond --validator-id v1 --amount 100 --fee 1 --nonce 1")
	fmt.Fprintln(os.Stderr, "  slash example: wallet sign --priv <hex> --kind validator_slash --validator-id v1 --basis-points 500 --fee 1 --nonce 1")
	fmt.Fprintln(os.Stderr, "  delegate example: wallet sign --priv <hex> --kind delegation_delegate --validator-id v1 --amount 25 --fee 1 --nonce 1")
	fmt.Fprintln(os.Stderr, "  settle example: wallet sign --priv <hex> --kind product_settle --to order-123 --amount 50 --fee 1 --nonce 1")
	fmt.Fprintln(os.Stderr, "  attest example: wallet sign --priv <hex> --kind product_attest --to proof-hash --validator-id v1 --amount 12 --basis-points 9000 --fee 1 --nonce 1")
}
