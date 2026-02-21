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
	to := fs.String("to", "", "recipient address")
	amount := fs.Uint64("amount", 0, "amount to transfer")
	fee := fs.Uint64("fee", 1, "transaction fee")
	nonce := fs.Uint64("nonce", 0, "sender nonce (required)")
	timestamp := fs.Int64("timestamp", 0, "unix ms timestamp (optional)")
	_ = fs.Parse(args)

	if *privateKey == "" || *to == "" || *amount == 0 || *nonce == 0 {
		fs.Usage()
		os.Exit(1)
	}

	tx := chain.Transaction{
		To:        chain.Address(*to),
		Amount:    *amount,
		Fee:       *fee,
		Nonce:     *nonce,
		Timestamp: *timestamp,
	}
	if err := chain.SignTransaction(&tx, *privateKey); err != nil {
		log.Fatalf("sign tx: %v", err)
	}
	printJSON(tx)
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
	fmt.Fprintln(os.Stderr, "  wallet sign --priv <hex> --to <addr> --amount <n> --fee <n> --nonce <n>")
}
