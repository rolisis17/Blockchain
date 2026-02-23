package node

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastpos/internal/chain"
	"fastpos/internal/p2p"
)

func newTestChain(t *testing.T) *chain.Chain {
	t.Helper()

	pub, _, valAddr, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, _, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	c, err := chain.New(chain.Config{
		GenesisAccounts: map[chain.Address]uint64{
			valAddr:   1_000,
			aliceAddr: 1_000,
		},
		GenesisValidators: []chain.GenesisValidator{
			{ID: "v1", PubKey: pub, Stake: 1000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	return c
}

func TestValidatorAdminToken(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{AdminToken: "secret"})

	payload := map[string]any{"id": "v1", "workWeight": 200}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/validators/work-weight", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", res.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/validators/work-weight", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Admin-Token", "secret")
	res2 := httptest.NewRecorder()
	srv.ServeHTTP(res2, req2)
	if res2.Code != http.StatusOK {
		t.Fatalf("expected 200 with token, got %d", res2.Code)
	}

	validators := c.GetValidators()
	if validators[0].WorkWeight != 200 {
		t.Fatalf("expected work weight update to 200, got %d", validators[0].WorkWeight)
	}
}

func TestValidatorLifecycleEndpoints(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{AdminToken: "secret"})

	bondBody := []byte(`{"id":"v1","amount":200}`)
	bondNoAuthReq := httptest.NewRequest(http.MethodPost, "/validators/bond", bytes.NewReader(bondBody))
	bondNoAuthReq.Header.Set("Content-Type", "application/json")
	bondNoAuthRes := httptest.NewRecorder()
	srv.ServeHTTP(bondNoAuthRes, bondNoAuthReq)
	if bondNoAuthRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token for /validators/bond, got %d", bondNoAuthRes.Code)
	}

	bondReq := httptest.NewRequest(http.MethodPost, "/validators/bond", bytes.NewReader(bondBody))
	bondReq.Header.Set("Content-Type", "application/json")
	bondReq.Header.Set("X-Admin-Token", "secret")
	bondRes := httptest.NewRecorder()
	srv.ServeHTTP(bondRes, bondReq)
	if bondRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /validators/bond, got %d", bondRes.Code)
	}

	slashReq := httptest.NewRequest(http.MethodPost, "/validators/slash", bytes.NewReader([]byte(`{"id":"v1","basisPoints":1000}`)))
	slashReq.Header.Set("Content-Type", "application/json")
	slashReq.Header.Set("X-Admin-Token", "secret")
	slashRes := httptest.NewRecorder()
	srv.ServeHTTP(slashRes, slashReq)
	if slashRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /validators/slash, got %d", slashRes.Code)
	}

	unbondReq := httptest.NewRequest(http.MethodPost, "/validators/unbond", bytes.NewReader([]byte(`{"id":"v1","amount":80}`)))
	unbondReq.Header.Set("Content-Type", "application/json")
	unbondReq.Header.Set("X-Admin-Token", "secret")
	unbondRes := httptest.NewRecorder()
	srv.ServeHTTP(unbondRes, unbondReq)
	if unbondRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /validators/unbond, got %d", unbondRes.Code)
	}

	jailReq := httptest.NewRequest(http.MethodPost, "/validators/jail", bytes.NewReader([]byte(`{"id":"v1","jailed":true}`)))
	jailReq.Header.Set("Content-Type", "application/json")
	jailReq.Header.Set("X-Admin-Token", "secret")
	jailRes := httptest.NewRecorder()
	srv.ServeHTTP(jailRes, jailReq)
	if jailRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /validators/jail, got %d", jailRes.Code)
	}

	validator, ok := c.GetValidator("v1")
	if !ok {
		t.Fatalf("expected validator v1 to exist")
	}
	if validator.Stake != 1_000 {
		t.Fatalf("expected validator stake 1000 after lifecycle ops, got %d", validator.Stake)
	}
	if !validator.Jailed {
		t.Fatalf("expected validator to be jailed")
	}

	metrics := c.GetMetrics()
	if metrics.ActiveValidatorsCount != 0 {
		t.Fatalf("expected 0 active validators when jailed, got %d", metrics.ActiveValidatorsCount)
	}
}

func TestDelegationsEndpointFilters(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	tx := chain.Transaction{
		Kind:        chain.TxKindDelegate,
		From:        aliceAddr,
		Amount:      30,
		Fee:         1,
		Nonce:       1,
		Timestamp:   time.Now().UnixMilli(),
		ValidatorID: "v1",
	}
	if err := chain.SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign delegate tx: %v", err)
	}
	if _, err := c.SubmitTx(tx); err != nil {
		t.Fatalf("submit delegate tx: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}

	assertDelegations := func(path string, expected int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", path, res.Code)
		}
		var delegations []chain.Delegation
		if err := json.NewDecoder(res.Body).Decode(&delegations); err != nil {
			t.Fatalf("decode delegations response for %s: %v", path, err)
		}
		if len(delegations) != expected {
			t.Fatalf("expected %d delegations for %s, got %d", expected, path, len(delegations))
		}
	}

	assertDelegations("/delegations", 1)
	assertDelegations("/delegations?validatorId=v1", 1)
	assertDelegations("/delegations?delegator="+string(aliceAddr), 1)
	assertDelegations("/delegations?delegator=unknown", 0)
}

func TestProductIntegrationEndpoints(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{ProductUnitPrice: 2})

	_, valPriv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	submit := func(path string, tx chain.Transaction) {
		t.Helper()
		body, _ := json.Marshal(tx)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("expected 202 for %s, got %d body=%s", path, res.Code, res.Body.String())
		}
	}

	settleTx := chain.Transaction{
		Kind:      chain.TxKindProductSettle,
		From:      aliceAddr,
		To:        chain.Address("order-42"),
		Amount:    200,
		Fee:       1,
		Nonce:     1,
		Timestamp: time.Now().UnixMilli(),
	}
	if err := chain.SignTransaction(&settleTx, alicePriv); err != nil {
		t.Fatalf("sign settle tx: %v", err)
	}
	submit("/product/settlements", settleTx)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce settlement block: %v", err)
	}

	attestTx := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("proof-ref"),
		Amount:      20,
		Fee:         1,
		Nonce:       1,
		Timestamp:   time.Now().UnixMilli(),
		ValidatorID: "v1",
		BasisPoints: 9000,
	}
	if err := chain.SignTransaction(&attestTx, valPriv); err != nil {
		t.Fatalf("sign attest tx: %v", err)
	}
	submit("/product/attestations", attestTx)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attestation block: %v", err)
	}

	proofsReq := httptest.NewRequest(http.MethodGet, "/product/proofs", nil)
	proofsRes := httptest.NewRecorder()
	srv.ServeHTTP(proofsRes, proofsReq)
	if proofsRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /product/proofs, got %d", proofsRes.Code)
	}
	var proofs []chain.ProductProof
	if err := json.NewDecoder(proofsRes.Body).Decode(&proofs); err != nil {
		t.Fatalf("decode proofs response: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("expected 1 proof, got %d", len(proofs))
	}

	pendingAttReq := httptest.NewRequest(http.MethodGet, "/product/attestations/pending", nil)
	pendingAttRes := httptest.NewRecorder()
	srv.ServeHTTP(pendingAttRes, pendingAttReq)
	if pendingAttRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /product/attestations/pending, got %d", pendingAttRes.Code)
	}
	var pendingAttestations []chain.ProductPendingAttestation
	if err := json.NewDecoder(pendingAttRes.Body).Decode(&pendingAttestations); err != nil {
		t.Fatalf("decode pending attestations response: %v", err)
	}
	if len(pendingAttestations) != 0 {
		t.Fatalf("expected 0 pending attestations, got %d", len(pendingAttestations))
	}

	challengeTx := chain.Transaction{
		Kind:      chain.TxKindProductChallenge,
		From:      aliceAddr,
		To:        chain.Address(proofs[0].ID),
		Amount:    15,
		Fee:       1,
		Nonce:     2,
		Timestamp: time.Now().UnixMilli(),
	}
	if err := chain.SignTransaction(&challengeTx, alicePriv); err != nil {
		t.Fatalf("sign challenge tx: %v", err)
	}
	submit("/product/challenges", challengeTx)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce challenge block: %v", err)
	}

	challengesReq := httptest.NewRequest(http.MethodGet, "/product/challenges", nil)
	challengesRes := httptest.NewRecorder()
	srv.ServeHTTP(challengesRes, challengesReq)
	if challengesRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /product/challenges, got %d", challengesRes.Code)
	}
	var challenges []chain.ProductChallenge
	if err := json.NewDecoder(challengesRes.Body).Decode(&challenges); err != nil {
		t.Fatalf("decode challenges response: %v", err)
	}
	if len(challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challenges))
	}

	resolveTx := chain.Transaction{
		Kind:        chain.TxKindProductResolveChallenge,
		To:          chain.Address(challenges[0].ID),
		Amount:      1,
		Fee:         1,
		Nonce:       2,
		Timestamp:   time.Now().UnixMilli(),
		BasisPoints: 500,
	}
	if err := chain.SignTransaction(&resolveTx, valPriv); err != nil {
		t.Fatalf("sign resolve tx: %v", err)
	}
	submit("/product/challenges/resolve", resolveTx)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce resolve block: %v", err)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/product/status", nil)
	statusRes := httptest.NewRecorder()
	srv.ServeHTTP(statusRes, statusReq)
	if statusRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /product/status, got %d", statusRes.Code)
	}
	var productStatus chain.ProductStatus
	if err := json.NewDecoder(statusRes.Body).Decode(&productStatus); err != nil {
		t.Fatalf("decode product status: %v", err)
	}
	if productStatus.ProofCount != 1 {
		t.Fatalf("expected proof count 1, got %d", productStatus.ProofCount)
	}
	if productStatus.OpenChallenges != 0 {
		t.Fatalf("expected no open challenges, got %d", productStatus.OpenChallenges)
	}
	if productStatus.AttestationTTLBlocks == 0 {
		t.Fatalf("expected attestation ttl blocks > 0")
	}
	if productStatus.ChallengeMaxOpenBlocks == 0 {
		t.Fatalf("expected challenge max open blocks > 0")
	}

	epochReq := httptest.NewRequest(http.MethodGet, "/epoch", nil)
	epochRes := httptest.NewRecorder()
	srv.ServeHTTP(epochRes, epochReq)
	if epochRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /epoch, got %d", epochRes.Code)
	}
	var epochInfo chain.EpochInfo
	if err := json.NewDecoder(epochRes.Body).Decode(&epochInfo); err != nil {
		t.Fatalf("decode epoch info: %v", err)
	}
	if epochInfo.Length == 0 {
		t.Fatalf("expected epoch length > 0")
	}

	quoteReq := httptest.NewRequest(http.MethodGet, "/product/billing/quote?units=7", nil)
	quoteRes := httptest.NewRecorder()
	srv.ServeHTTP(quoteRes, quoteReq)
	if quoteRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /product/billing/quote, got %d", quoteRes.Code)
	}
	var quote struct {
		Units     uint64 `json:"units"`
		UnitPrice uint64 `json:"unitPrice"`
		Amount    uint64 `json:"amount"`
	}
	if err := json.NewDecoder(quoteRes.Body).Decode(&quote); err != nil {
		t.Fatalf("decode quote: %v", err)
	}
	if quote.Units != 7 || quote.UnitPrice != 2 || quote.Amount != 14 {
		t.Fatalf("unexpected quote: %+v", quote)
	}
}

func TestProductReadEndpointFilters(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{ProductUnitPrice: 2})

	_, valPriv, valAddr, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	const tsBase int64 = 1_700_000_700_000

	submit := func(path string, tx chain.Transaction) {
		t.Helper()
		body, _ := json.Marshal(tx)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("expected 202 for %s, got %d body=%s", path, res.Code, res.Body.String())
		}
	}

	settle1 := chain.Transaction{
		Kind:      chain.TxKindProductSettle,
		From:      aliceAddr,
		To:        chain.Address("order-42"),
		Amount:    100,
		Fee:       1,
		Nonce:     1,
		Timestamp: tsBase + 1,
	}
	if err := chain.SignTransaction(&settle1, alicePriv); err != nil {
		t.Fatalf("sign settle1: %v", err)
	}
	submit("/product/settlements", settle1)
	pendingLookupReq := httptest.NewRequest(http.MethodGet, "/product/settlements/lookup?payer="+string(aliceAddr)+"&reference=order-42&includePending=true", nil)
	pendingLookupRes := httptest.NewRecorder()
	srv.ServeHTTP(pendingLookupRes, pendingLookupReq)
	if pendingLookupRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for pending settlement lookup, got %d body=%s", pendingLookupRes.Code, pendingLookupRes.Body.String())
	}
	var pendingLookup struct {
		State string `json:"state"`
		TxID  string `json:"txId"`
	}
	if err := json.NewDecoder(pendingLookupRes.Body).Decode(&pendingLookup); err != nil {
		t.Fatalf("decode pending settlement lookup response: %v", err)
	}
	if pendingLookup.State != chain.TxStatePending || pendingLookup.TxID == "" {
		t.Fatalf("unexpected pending settlement lookup response: %+v", pendingLookup)
	}

	settle2 := chain.Transaction{
		Kind:      chain.TxKindProductSettle,
		From:      aliceAddr,
		To:        chain.Address("order-99"),
		Amount:    120,
		Fee:       1,
		Nonce:     2,
		Timestamp: tsBase + 10,
	}
	if err := chain.SignTransaction(&settle2, alicePriv); err != nil {
		t.Fatalf("sign settle2: %v", err)
	}
	submit("/product/settlements", settle2)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce settlement block: %v", err)
	}

	attestTx := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("proof-ref-filtered"),
		Amount:      25,
		Fee:         1,
		Nonce:       1,
		Timestamp:   tsBase + 20,
		ValidatorID: "v1",
		BasisPoints: 9_200,
	}
	if err := chain.SignTransaction(&attestTx, valPriv); err != nil {
		t.Fatalf("sign attest tx: %v", err)
	}
	submit("/product/attestations", attestTx)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attest block: %v", err)
	}

	proofsReq := httptest.NewRequest(http.MethodGet, "/product/proofs", nil)
	proofsRes := httptest.NewRecorder()
	srv.ServeHTTP(proofsRes, proofsReq)
	if proofsRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /product/proofs, got %d", proofsRes.Code)
	}
	var proofs []chain.ProductProof
	if err := json.NewDecoder(proofsRes.Body).Decode(&proofs); err != nil {
		t.Fatalf("decode proofs: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("expected 1 proof, got %d", len(proofs))
	}

	challengeTx := chain.Transaction{
		Kind:      chain.TxKindProductChallenge,
		From:      aliceAddr,
		To:        chain.Address(proofs[0].ID),
		Amount:    15,
		Fee:       1,
		Nonce:     3,
		Timestamp: tsBase + 30,
	}
	if err := chain.SignTransaction(&challengeTx, alicePriv); err != nil {
		t.Fatalf("sign challenge tx: %v", err)
	}
	submit("/product/challenges", challengeTx)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce challenge block: %v", err)
	}

	assertLen := func(path string, expected int, out any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d body=%s", path, res.Code, res.Body.String())
		}
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			t.Fatalf("decode %s response: %v", path, err)
		}
		switch v := out.(type) {
		case *[]chain.ProductSettlement:
			if len(*v) != expected {
				t.Fatalf("expected %d settlements for %s, got %d", expected, path, len(*v))
			}
		case *[]chain.ProductProof:
			if len(*v) != expected {
				t.Fatalf("expected %d proofs for %s, got %d", expected, path, len(*v))
			}
		case *[]chain.ProductChallenge:
			if len(*v) != expected {
				t.Fatalf("expected %d challenges for %s, got %d", expected, path, len(*v))
			}
		default:
			t.Fatalf("unsupported assert type %T", out)
		}
	}

	var settlements []chain.ProductSettlement
	assertLen("/product/settlements?reference=order-42", 1, &settlements)
	if len(settlements) != 1 {
		t.Fatalf("expected one settlement for order-42")
	}
	lookupReq := httptest.NewRequest(http.MethodGet, "/product/settlements/lookup?payer="+string(aliceAddr)+"&reference=order-42", nil)
	lookupRes := httptest.NewRecorder()
	srv.ServeHTTP(lookupRes, lookupReq)
	if lookupRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /product/settlements/lookup, got %d body=%s", lookupRes.Code, lookupRes.Body.String())
	}
	var lookedUp struct {
		State      string                  `json:"state"`
		Settlement chain.ProductSettlement `json:"settlement"`
	}
	if err := json.NewDecoder(lookupRes.Body).Decode(&lookedUp); err != nil {
		t.Fatalf("decode settlement lookup response: %v", err)
	}
	if lookedUp.State != chain.TxStateFinalized {
		t.Fatalf("expected finalized settlement lookup state, got %q", lookedUp.State)
	}
	if lookedUp.Settlement.ID != settlements[0].ID {
		t.Fatalf("expected lookup settlement id %s, got %s", settlements[0].ID, lookedUp.Settlement.ID)
	}
	lookupMissingReq := httptest.NewRequest(http.MethodGet, "/product/settlements/lookup?payer="+string(aliceAddr)+"&reference=missing", nil)
	lookupMissingRes := httptest.NewRecorder()
	srv.ServeHTTP(lookupMissingRes, lookupMissingReq)
	if lookupMissingRes.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing settlement lookup, got %d", lookupMissingRes.Code)
	}
	lookupBadIncludePendingReq := httptest.NewRequest(http.MethodGet, "/product/settlements/lookup?payer="+string(aliceAddr)+"&reference=order-42&includePending=maybe", nil)
	lookupBadIncludePendingRes := httptest.NewRecorder()
	srv.ServeHTTP(lookupBadIncludePendingRes, lookupBadIncludePendingReq)
	if lookupBadIncludePendingRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad settlement includePending query, got %d", lookupBadIncludePendingRes.Code)
	}
	settlements = nil
	assertLen("/product/settlements?payer="+string(aliceAddr), 2, &settlements)
	settlements = nil
	assertLen("/product/settlements?epoch=0", 2, &settlements)
	settlements = nil
	assertLen("/product/settlements?minAmount=110", 1, &settlements)
	settlements = nil
	assertLen("/product/settlements?maxAmount=110", 1, &settlements)
	settlements = nil
	assertLen("/product/settlements?sinceMs="+strconv.FormatInt(tsBase+10, 10), 1, &settlements)
	settlements = nil
	assertLen("/product/settlements?untilMs="+strconv.FormatInt(tsBase+1, 10), 1, &settlements)
	settlements = nil
	assertLen("/product/settlements?payer="+string(aliceAddr)+"&limit=1", 1, &settlements)
	settlements = nil
	assertLen("/product/settlements?payer="+string(aliceAddr)+"&limit=1&offset=1", 1, &settlements)
	settlements = nil
	assertLen("/product/settlements?payer="+string(aliceAddr)+"&limit=1&offset=5", 0, &settlements)
	metaReq := httptest.NewRequest(http.MethodGet, "/product/settlements?payer="+string(aliceAddr)+"&limit=1&withMeta=true", nil)
	metaRes := httptest.NewRecorder()
	srv.ServeHTTP(metaRes, metaReq)
	if metaRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for settlement metadata response, got %d", metaRes.Code)
	}
	var metaPayload struct {
		Items   []chain.ProductSettlement `json:"items"`
		Total   int                       `json:"total"`
		Offset  int                       `json:"offset"`
		Limit   int                       `json:"limit"`
		Count   int                       `json:"count"`
		HasMore bool                      `json:"hasMore"`
	}
	if err := json.NewDecoder(metaRes.Body).Decode(&metaPayload); err != nil {
		t.Fatalf("decode settlement metadata response: %v", err)
	}
	if metaPayload.Total != 2 || metaPayload.Count != 1 || !metaPayload.HasMore {
		t.Fatalf("unexpected settlement metadata payload: %+v", metaPayload)
	}

	var filteredProofs []chain.ProductProof
	assertLen("/product/proofs?id="+proofs[0].ID, 1, &filteredProofs)
	filteredProofs = nil
	assertLen("/product/proofs?reporter="+string(valAddr), 1, &filteredProofs)
	filteredProofs = nil
	assertLen("/product/proofs?epoch="+strconv.FormatUint(proofs[0].Epoch, 10), 1, &filteredProofs)
	filteredProofs = nil
	assertLen("/product/proofs?minScore=20", 1, &filteredProofs)
	filteredProofs = nil
	assertLen("/product/proofs?minScore=24", 0, &filteredProofs)

	var openChallenges []chain.ProductChallenge
	assertLen("/product/challenges?proofId="+proofs[0].ID+"&openOnly=true", 1, &openChallenges)
	if len(openChallenges) != 1 {
		t.Fatalf("expected one open challenge for proof %s", proofs[0].ID)
	}

	var challengeByID []chain.ProductChallenge
	assertLen("/product/challenges?id="+openChallenges[0].ID, 1, &challengeByID)

	var challengeByChallenger []chain.ProductChallenge
	assertLen("/product/challenges?challenger="+string(aliceAddr), 1, &challengeByChallenger)
	challengeByChallenger = nil
	assertLen("/product/challenges?successful=false", 1, &challengeByChallenger)
	challengeByChallenger = nil
	assertLen("/product/challenges?minBond=20", 0, &challengeByChallenger)
	challengeByChallenger = nil
	assertLen("/product/challenges?sinceMs="+strconv.FormatInt(tsBase+30, 10), 1, &challengeByChallenger)
	challengeByChallenger = nil
	assertLen("/product/challenges?untilMs="+strconv.FormatInt(tsBase+20, 10), 0, &challengeByChallenger)

	badSettlementReq := httptest.NewRequest(http.MethodGet, "/product/settlements?minAmount=bad", nil)
	badSettlementRes := httptest.NewRecorder()
	srv.ServeHTTP(badSettlementRes, badSettlementReq)
	if badSettlementRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad settlement filter query, got %d", badSettlementRes.Code)
	}
	badSettlementOffsetReq := httptest.NewRequest(http.MethodGet, "/product/settlements?offset=-1", nil)
	badSettlementOffsetRes := httptest.NewRecorder()
	srv.ServeHTTP(badSettlementOffsetRes, badSettlementOffsetReq)
	if badSettlementOffsetRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative settlement offset query, got %d", badSettlementOffsetRes.Code)
	}
	badSettlementMetaReq := httptest.NewRequest(http.MethodGet, "/product/settlements?withMeta=maybe", nil)
	badSettlementMetaRes := httptest.NewRecorder()
	srv.ServeHTTP(badSettlementMetaRes, badSettlementMetaReq)
	if badSettlementMetaRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid settlement withMeta query, got %d", badSettlementMetaRes.Code)
	}
	badProofReq := httptest.NewRequest(http.MethodGet, "/product/proofs?epoch=bad", nil)
	badProofRes := httptest.NewRecorder()
	srv.ServeHTTP(badProofRes, badProofReq)
	if badProofRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad proof filter query, got %d", badProofRes.Code)
	}
	badProofIncludeInvalidReq := httptest.NewRequest(http.MethodGet, "/product/proofs?includeInvalid=bad", nil)
	badProofIncludeInvalidRes := httptest.NewRecorder()
	srv.ServeHTTP(badProofIncludeInvalidRes, badProofIncludeInvalidReq)
	if badProofIncludeInvalidRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad includeInvalid proof query, got %d", badProofIncludeInvalidRes.Code)
	}
	badChallengeOpenOnlyReq := httptest.NewRequest(http.MethodGet, "/product/challenges?openOnly=bad", nil)
	badChallengeOpenOnlyRes := httptest.NewRecorder()
	srv.ServeHTTP(badChallengeOpenOnlyRes, badChallengeOpenOnlyReq)
	if badChallengeOpenOnlyRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad openOnly challenge query, got %d", badChallengeOpenOnlyRes.Code)
	}
}

func TestProductSettlementIdempotentSubmit(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	postSettlement := func(path string, tx chain.Transaction) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(tx)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		return res
	}

	first := chain.Transaction{
		Kind:      chain.TxKindProductSettle,
		From:      aliceAddr,
		To:        chain.Address("invoice-idem-1"),
		Amount:    100,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_500_001,
	}
	if err := chain.SignTransaction(&first, alicePriv); err != nil {
		t.Fatalf("sign first settlement tx: %v", err)
	}
	firstRes := postSettlement("/product/settlements", first)
	if firstRes.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for first settlement submit, got %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	duplicate := chain.Transaction{
		Kind:      chain.TxKindProductSettle,
		From:      aliceAddr,
		To:        chain.Address("invoice-idem-1"),
		Amount:    100,
		Fee:       1,
		Nonce:     2,
		Timestamp: 1_700_000_500_002,
	}
	if err := chain.SignTransaction(&duplicate, alicePriv); err != nil {
		t.Fatalf("sign duplicate settlement tx: %v", err)
	}

	dupNoIdemRes := postSettlement("/product/settlements", duplicate)
	if dupNoIdemRes.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate settlement without idempotent flag, got %d body=%s", dupNoIdemRes.Code, dupNoIdemRes.Body.String())
	}

	dupPendingRes := postSettlement("/product/settlements?idempotent=true", duplicate)
	if dupPendingRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent pending duplicate settlement, got %d body=%s", dupPendingRes.Code, dupPendingRes.Body.String())
	}
	var pendingResp struct {
		OK         bool   `json:"ok"`
		Idempotent bool   `json:"idempotent"`
		Duplicate  bool   `json:"duplicate"`
		State      string `json:"state"`
		TxID       string `json:"txId"`
	}
	if err := json.NewDecoder(dupPendingRes.Body).Decode(&pendingResp); err != nil {
		t.Fatalf("decode idempotent pending duplicate response: %v", err)
	}
	if !pendingResp.OK || !pendingResp.Idempotent || !pendingResp.Duplicate || pendingResp.State != chain.TxStatePending || pendingResp.TxID == "" {
		t.Fatalf("unexpected idempotent pending duplicate response: %+v", pendingResp)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce settlement block: %v", err)
	}

	dupFinalRes := postSettlement("/product/settlements?idempotent=true", duplicate)
	if dupFinalRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent finalized duplicate settlement, got %d body=%s", dupFinalRes.Code, dupFinalRes.Body.String())
	}
	var finalResp struct {
		OK         bool                    `json:"ok"`
		Idempotent bool                    `json:"idempotent"`
		Duplicate  bool                    `json:"duplicate"`
		State      string                  `json:"state"`
		Settlement chain.ProductSettlement `json:"settlement"`
	}
	if err := json.NewDecoder(dupFinalRes.Body).Decode(&finalResp); err != nil {
		t.Fatalf("decode idempotent finalized duplicate response: %v", err)
	}
	if !finalResp.OK || !finalResp.Idempotent || !finalResp.Duplicate || finalResp.State != chain.TxStateFinalized {
		t.Fatalf("unexpected idempotent finalized duplicate response: %+v", finalResp)
	}
	if finalResp.Settlement.Payer != aliceAddr || finalResp.Settlement.Reference != "invoice-idem-1" {
		t.Fatalf("unexpected finalized settlement in idempotent response: %+v", finalResp.Settlement)
	}
}

func TestProductSettlementStatsEndpoint(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	postSettlement := func(tx chain.Transaction) {
		t.Helper()
		body, _ := json.Marshal(tx)
		req := httptest.NewRequest(http.MethodPost, "/product/settlements", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("expected 202 for settlement submit, got %d body=%s", res.Code, res.Body.String())
		}
	}

	settle1 := chain.Transaction{
		Kind:        chain.TxKindProductSettle,
		From:        aliceAddr,
		To:          chain.Address("stats-order-1"),
		ValidatorID: "v1",
		Amount:      100,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_800_001,
	}
	if err := chain.SignTransaction(&settle1, alicePriv); err != nil {
		t.Fatalf("sign settle1: %v", err)
	}
	postSettlement(settle1)

	settle2 := chain.Transaction{
		Kind:        chain.TxKindProductSettle,
		From:        aliceAddr,
		To:          chain.Address("stats-order-2"),
		ValidatorID: "v1",
		Amount:      120,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_800_010,
	}
	if err := chain.SignTransaction(&settle2, alicePriv); err != nil {
		t.Fatalf("sign settle2: %v", err)
	}
	postSettlement(settle2)

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce settlements block: %v", err)
	}

	getStats := func(path string) (int, struct {
		Count       int    `json:"count"`
		TotalAmount uint64 `json:"totalAmount"`
		ByValidator []struct {
			ValidatorID string `json:"validatorId"`
			Count       int    `json:"count"`
			Amount      uint64 `json:"amount"`
		} `json:"byValidator"`
		ByEpoch []struct {
			Epoch  uint64 `json:"epoch"`
			Count  int    `json:"count"`
			Amount uint64 `json:"amount"`
		} `json:"byEpoch"`
	}) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		var payload struct {
			Count       int    `json:"count"`
			TotalAmount uint64 `json:"totalAmount"`
			ByValidator []struct {
				ValidatorID string `json:"validatorId"`
				Count       int    `json:"count"`
				Amount      uint64 `json:"amount"`
			} `json:"byValidator"`
			ByEpoch []struct {
				Epoch  uint64 `json:"epoch"`
				Count  int    `json:"count"`
				Amount uint64 `json:"amount"`
			} `json:"byEpoch"`
		}
		if res.Code == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
				t.Fatalf("decode stats response for %s: %v", path, err)
			}
		}
		return res.Code, payload
	}

	code, stats := getStats("/product/settlements/stats")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for settlement stats, got %d", code)
	}
	if stats.Count != 2 || stats.TotalAmount != 220 {
		t.Fatalf("unexpected settlement stats summary: %+v", stats)
	}
	if len(stats.ByValidator) != 1 {
		t.Fatalf("expected 1 validator aggregation, got %d", len(stats.ByValidator))
	}
	if stats.ByValidator[0].ValidatorID != "v1" || stats.ByValidator[0].Count != 2 || stats.ByValidator[0].Amount != 220 {
		t.Fatalf("unexpected validator settlement aggregation: %+v", stats.ByValidator[0])
	}
	if len(stats.ByEpoch) != 1 {
		t.Fatalf("expected 1 epoch aggregation, got %d", len(stats.ByEpoch))
	}
	if stats.ByEpoch[0].Count != 2 || stats.ByEpoch[0].Amount != 220 {
		t.Fatalf("unexpected epoch settlement aggregation: %+v", stats.ByEpoch[0])
	}

	code, stats = getStats("/product/settlements/stats?reference=stats-order-1")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for settlement stats reference filter, got %d", code)
	}
	if stats.Count != 1 || stats.TotalAmount != 100 {
		t.Fatalf("unexpected settlement stats reference summary: %+v", stats)
	}

	code, stats = getStats("/product/settlements/stats?validatorId=v1&minAmount=110")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for settlement stats amount filter, got %d", code)
	}
	if stats.Count != 1 || stats.TotalAmount != 120 {
		t.Fatalf("unexpected settlement stats amount summary: %+v", stats)
	}

	code, stats = getStats("/product/settlements/stats?sinceMs=1700000800010")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for settlement stats since filter, got %d", code)
	}
	if stats.Count != 1 || stats.TotalAmount != 120 {
		t.Fatalf("unexpected settlement stats since summary: %+v", stats)
	}

	badReq := httptest.NewRequest(http.MethodGet, "/product/settlements/stats?epoch=bad", nil)
	badRes := httptest.NewRecorder()
	srv.ServeHTTP(badRes, badReq)
	if badRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad settlement stats query, got %d", badRes.Code)
	}
}

func TestProductChallengeStatsEndpoint(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, valPriv, valAddr, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}

	submit := func(path string, tx chain.Transaction) {
		t.Helper()
		body, _ := json.Marshal(tx)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("expected 202 for %s, got %d body=%s", path, res.Code, res.Body.String())
		}
	}

	attest1 := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("stats-proof-a"),
		Amount:      21,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_900_001,
		ValidatorID: "v1",
		BasisPoints: 9_000,
	}
	if err := chain.SignTransaction(&attest1, valPriv); err != nil {
		t.Fatalf("sign attest1: %v", err)
	}
	submit("/product/attestations", attest1)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attest1 block: %v", err)
	}

	proofs := c.GetProductProofs()
	if len(proofs) != 1 {
		t.Fatalf("expected 1 proof after attest1, got %d", len(proofs))
	}
	proofAID := proofs[0].ID

	challenge1 := chain.Transaction{
		Kind:      chain.TxKindProductChallenge,
		From:      aliceAddr,
		To:        chain.Address(proofAID),
		Amount:    15,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_900_010,
	}
	if err := chain.SignTransaction(&challenge1, alicePriv); err != nil {
		t.Fatalf("sign challenge1: %v", err)
	}
	submit("/product/challenges", challenge1)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce challenge1 block: %v", err)
	}

	attest2 := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("stats-proof-b"),
		Amount:      22,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_900_020,
		ValidatorID: "v1",
		BasisPoints: 9_100,
	}
	if err := chain.SignTransaction(&attest2, valPriv); err != nil {
		t.Fatalf("sign attest2: %v", err)
	}
	submit("/product/attestations", attest2)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attest2 block: %v", err)
	}

	proofs = c.GetProductProofs()
	proofBID := ""
	for _, proof := range proofs {
		if proof.ProofRef == "stats-proof-b" {
			proofBID = proof.ID
			break
		}
	}
	if proofBID == "" {
		t.Fatalf("missing proof id for stats-proof-b")
	}

	challenge2 := chain.Transaction{
		Kind:      chain.TxKindProductChallenge,
		From:      aliceAddr,
		To:        chain.Address(proofBID),
		Amount:    25,
		Fee:       1,
		Nonce:     2,
		Timestamp: 1_700_000_900_030,
	}
	if err := chain.SignTransaction(&challenge2, alicePriv); err != nil {
		t.Fatalf("sign challenge2: %v", err)
	}
	submit("/product/challenges", challenge2)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce challenge2 block: %v", err)
	}

	resolve2 := chain.Transaction{
		Kind:        chain.TxKindProductResolveChallenge,
		To:          chain.Address(challenge2.ID()),
		Fee:         1,
		Nonce:       3,
		Timestamp:   1_700_000_900_040,
		BasisPoints: 0,
	}
	if err := chain.SignTransaction(&resolve2, valPriv); err != nil {
		t.Fatalf("sign resolve2: %v", err)
	}
	submit("/product/challenges/resolve", resolve2)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce resolve2 block: %v", err)
	}

	getStats := func(path string) (int, struct {
		Count        int    `json:"count"`
		OpenCount    int    `json:"openCount"`
		ClosedCount  int    `json:"closedCount"`
		Successful   int    `json:"successful"`
		Rejected     int    `json:"rejected"`
		TotalBond    uint64 `json:"totalBond"`
		OpenBond     uint64 `json:"openBond"`
		ResolvedBond uint64 `json:"resolvedBond"`
		ByChallenger []struct {
			Challenger string `json:"challenger"`
			Count      int    `json:"count"`
			OpenCount  int    `json:"openCount"`
			Successful int    `json:"successful"`
			Rejected   int    `json:"rejected"`
			Bond       uint64 `json:"bond"`
		} `json:"byChallenger"`
		ByResolver []struct {
			Resolver   string `json:"resolver"`
			Count      int    `json:"count"`
			Successful int    `json:"successful"`
			Rejected   int    `json:"rejected"`
			Bond       uint64 `json:"bond"`
		} `json:"byResolver"`
	}) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		var payload struct {
			Count        int    `json:"count"`
			OpenCount    int    `json:"openCount"`
			ClosedCount  int    `json:"closedCount"`
			Successful   int    `json:"successful"`
			Rejected     int    `json:"rejected"`
			TotalBond    uint64 `json:"totalBond"`
			OpenBond     uint64 `json:"openBond"`
			ResolvedBond uint64 `json:"resolvedBond"`
			ByChallenger []struct {
				Challenger string `json:"challenger"`
				Count      int    `json:"count"`
				OpenCount  int    `json:"openCount"`
				Successful int    `json:"successful"`
				Rejected   int    `json:"rejected"`
				Bond       uint64 `json:"bond"`
			} `json:"byChallenger"`
			ByResolver []struct {
				Resolver   string `json:"resolver"`
				Count      int    `json:"count"`
				Successful int    `json:"successful"`
				Rejected   int    `json:"rejected"`
				Bond       uint64 `json:"bond"`
			} `json:"byResolver"`
		}
		if res.Code == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
				t.Fatalf("decode challenge stats response for %s: %v", path, err)
			}
		}
		return res.Code, payload
	}

	code, stats := getStats("/product/challenges/stats")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for challenge stats, got %d", code)
	}
	if stats.Count != 2 || stats.OpenCount != 1 || stats.ClosedCount != 1 || stats.Successful != 0 || stats.Rejected != 1 {
		t.Fatalf("unexpected challenge stats summary: %+v", stats)
	}
	if stats.TotalBond != 40 || stats.OpenBond != 15 || stats.ResolvedBond != 25 {
		t.Fatalf("unexpected challenge bond summary: %+v", stats)
	}
	if len(stats.ByChallenger) != 1 {
		t.Fatalf("expected 1 challenger aggregation, got %d", len(stats.ByChallenger))
	}
	if stats.ByChallenger[0].Challenger != string(aliceAddr) || stats.ByChallenger[0].Count != 2 || stats.ByChallenger[0].OpenCount != 1 || stats.ByChallenger[0].Rejected != 1 || stats.ByChallenger[0].Bond != 40 {
		t.Fatalf("unexpected challenger aggregation: %+v", stats.ByChallenger[0])
	}
	if len(stats.ByResolver) != 1 {
		t.Fatalf("expected 1 resolver aggregation, got %d", len(stats.ByResolver))
	}
	if stats.ByResolver[0].Resolver != string(valAddr) || stats.ByResolver[0].Count != 1 || stats.ByResolver[0].Rejected != 1 || stats.ByResolver[0].Bond != 25 {
		t.Fatalf("unexpected resolver aggregation: %+v", stats.ByResolver[0])
	}

	code, stats = getStats("/product/challenges/stats?openOnly=true")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for challenge stats openOnly filter, got %d", code)
	}
	if stats.Count != 1 || stats.OpenCount != 1 || stats.TotalBond != 15 {
		t.Fatalf("unexpected challenge openOnly summary: %+v", stats)
	}

	code, stats = getStats("/product/challenges/stats?resolver=" + string(valAddr))
	if code != http.StatusOK {
		t.Fatalf("expected 200 for challenge stats resolver filter, got %d", code)
	}
	if stats.Count != 1 || stats.ResolvedBond != 25 {
		t.Fatalf("unexpected challenge resolver summary: %+v", stats)
	}

	code, stats = getStats("/product/challenges/stats?minBond=20")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for challenge stats minBond filter, got %d", code)
	}
	if stats.Count != 1 || stats.TotalBond != 25 {
		t.Fatalf("unexpected challenge minBond summary: %+v", stats)
	}

	badReq := httptest.NewRequest(http.MethodGet, "/product/challenges/stats?openOnly=bad", nil)
	badRes := httptest.NewRecorder()
	srv.ServeHTTP(badRes, badReq)
	if badRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad challenge stats query, got %d", badRes.Code)
	}
}

func TestProductAttestationStatsEndpoint(t *testing.T) {
	val1Pub, val1Priv, val1Addr, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator-1 keypair: %v", err)
	}
	val2Pub, _, val2Addr, err := chain.DeterministicKeypair("validator-two")
	if err != nil {
		t.Fatalf("validator-2 keypair: %v", err)
	}
	c, err := chain.New(chain.Config{
		GenesisAccounts: map[chain.Address]uint64{
			val1Addr: 1_000,
			val2Addr: 1_000,
		},
		GenesisValidators: []chain.GenesisValidator{
			{ID: "v1", PubKey: val1Pub, Stake: 1_000, WorkWeight: 100, Active: true},
			{ID: "v2", PubKey: val2Pub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	srv := NewServer(c, Config{})

	submit := func(path string, tx chain.Transaction) {
		t.Helper()
		body, _ := json.Marshal(tx)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("expected 202 for %s, got %d body=%s", path, res.Code, res.Body.String())
		}
	}

	att1 := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("pending-proof-1"),
		Amount:      10,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_001_000_001,
		ValidatorID: "v1",
		BasisPoints: 9_200,
	}
	if err := chain.SignTransaction(&att1, val1Priv); err != nil {
		t.Fatalf("sign att1: %v", err)
	}
	submit("/product/attestations", att1)

	att2 := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("pending-proof-2"),
		Amount:      11,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_001_000_010,
		ValidatorID: "v1",
		BasisPoints: 9_300,
	}
	if err := chain.SignTransaction(&att2, val1Priv); err != nil {
		t.Fatalf("sign att2: %v", err)
	}
	submit("/product/attestations", att2)

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce pending attestation block: %v", err)
	}

	expectedPending := c.GetProductPendingAttestations()
	if len(expectedPending) != 2 {
		t.Fatalf("expected 2 pending attestations, got %d", len(expectedPending))
	}
	expectedRequired := uint64(0)
	expectedCollected := uint64(0)
	expectedProgressBpsSum := uint64(0)
	for _, att := range expectedPending {
		expectedRequired += att.RequiredStake
		expectedCollected += att.CollectedStake
		progress := uint64(0)
		if att.RequiredStake > 0 {
			progress = (att.CollectedStake * 10_000) / att.RequiredStake
		}
		expectedProgressBpsSum += progress
	}
	expectedAvgProgress := expectedProgressBpsSum / uint64(len(expectedPending))

	getStats := func(path string) (int, struct {
		Count               int    `json:"count"`
		TotalRequiredStake  uint64 `json:"totalRequiredStake"`
		TotalCollectedStake uint64 `json:"totalCollectedStake"`
		AverageProgressBps  uint64 `json:"averageProgressBps"`
		ByValidator         []struct {
			ValidatorID    string `json:"validatorId"`
			Count          int    `json:"count"`
			RequiredStake  uint64 `json:"requiredStake"`
			CollectedStake uint64 `json:"collectedStake"`
		} `json:"byValidator"`
	}) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		var payload struct {
			Count               int    `json:"count"`
			TotalRequiredStake  uint64 `json:"totalRequiredStake"`
			TotalCollectedStake uint64 `json:"totalCollectedStake"`
			AverageProgressBps  uint64 `json:"averageProgressBps"`
			ByValidator         []struct {
				ValidatorID    string `json:"validatorId"`
				Count          int    `json:"count"`
				RequiredStake  uint64 `json:"requiredStake"`
				CollectedStake uint64 `json:"collectedStake"`
			} `json:"byValidator"`
		}
		if res.Code == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
				t.Fatalf("decode attestation stats response for %s: %v", path, err)
			}
		}
		return res.Code, payload
	}

	code, stats := getStats("/product/attestations/stats")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for attestation stats, got %d", code)
	}
	if stats.Count != 2 || stats.TotalRequiredStake != expectedRequired || stats.TotalCollectedStake != expectedCollected || stats.AverageProgressBps != expectedAvgProgress {
		t.Fatalf("unexpected attestation stats summary: %+v", stats)
	}
	if len(stats.ByValidator) != 1 {
		t.Fatalf("expected 1 validator aggregation, got %d", len(stats.ByValidator))
	}
	if stats.ByValidator[0].ValidatorID != "v1" || stats.ByValidator[0].Count != 2 || stats.ByValidator[0].RequiredStake != expectedRequired || stats.ByValidator[0].CollectedStake != expectedCollected {
		t.Fatalf("unexpected attestation by-validator stats: %+v", stats.ByValidator[0])
	}

	code, stats = getStats("/product/attestations/stats?proofRef=pending-proof-1")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for attestation stats proofRef filter, got %d", code)
	}
	if stats.Count != 1 {
		t.Fatalf("expected 1 attestation for proofRef filter, got %d", stats.Count)
	}

	code, stats = getStats("/product/attestations/stats?sinceMs=1700001000010")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for attestation stats sinceMs filter, got %d", code)
	}
	if stats.Count != 1 {
		t.Fatalf("expected 1 attestation for sinceMs filter, got %d", stats.Count)
	}

	badReq := httptest.NewRequest(http.MethodGet, "/product/attestations/stats?minCollectedStake=bad", nil)
	badRes := httptest.NewRecorder()
	srv.ServeHTTP(badRes, badReq)
	if badRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad attestation stats query, got %d", badRes.Code)
	}
}

func TestProductAttestationChallengeResolveIdempotentSubmit(t *testing.T) {
	valPub, valPriv, valAddr, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	c, err := chain.New(chain.Config{
		BaseReward:        0,
		MinTxFee:          1,
		EpochLengthBlocks: 8,
		GenesisAccounts: map[chain.Address]uint64{
			valAddr:   1_000,
			aliceAddr: 1_000,
		},
		GenesisValidators: []chain.GenesisValidator{
			{ID: "v1", PubKey: valPub, Stake: 1_000, WorkWeight: 100, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	srv := NewServer(c, Config{})

	post := func(path string, tx chain.Transaction) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(tx)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		return res
	}

	attest1 := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("idem-proof-ref"),
		Amount:      25,
		Fee:         1,
		Nonce:       1,
		Timestamp:   1_700_000_600_001,
		ValidatorID: "v1",
		BasisPoints: 9_100,
	}
	if err := chain.SignTransaction(&attest1, valPriv); err != nil {
		t.Fatalf("sign attest1 tx: %v", err)
	}
	attest1Res := post("/product/attestations", attest1)
	if attest1Res.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for attest1 submit, got %d body=%s", attest1Res.Code, attest1Res.Body.String())
	}

	attestDupPending := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("idem-proof-ref"),
		Amount:      25,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_600_002,
		ValidatorID: "v1",
		BasisPoints: 9_100,
	}
	if err := chain.SignTransaction(&attestDupPending, valPriv); err != nil {
		t.Fatalf("sign attestDupPending tx: %v", err)
	}
	attestDupNoIdemRes := post("/product/attestations", attestDupPending)
	if attestDupNoIdemRes.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate pending attest without idempotent flag, got %d body=%s", attestDupNoIdemRes.Code, attestDupNoIdemRes.Body.String())
	}
	attestDupPendingRes := post("/product/attestations?idempotent=true", attestDupPending)
	if attestDupPendingRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent pending attest duplicate, got %d body=%s", attestDupPendingRes.Code, attestDupPendingRes.Body.String())
	}
	var attestPendingResp struct {
		OK         bool   `json:"ok"`
		Idempotent bool   `json:"idempotent"`
		Duplicate  bool   `json:"duplicate"`
		State      string `json:"state"`
		TxID       string `json:"txId"`
	}
	if err := json.NewDecoder(attestDupPendingRes.Body).Decode(&attestPendingResp); err != nil {
		t.Fatalf("decode attest pending idempotent response: %v", err)
	}
	if !attestPendingResp.OK || !attestPendingResp.Idempotent || !attestPendingResp.Duplicate || attestPendingResp.State != chain.TxStatePending || attestPendingResp.TxID == "" {
		t.Fatalf("unexpected attest pending idempotent response: %+v", attestPendingResp)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce attestation block: %v", err)
	}

	attestDupFinal := chain.Transaction{
		Kind:        chain.TxKindProductAttest,
		To:          chain.Address("idem-proof-ref"),
		Amount:      25,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_600_003,
		ValidatorID: "v1",
		BasisPoints: 9_100,
	}
	if err := chain.SignTransaction(&attestDupFinal, valPriv); err != nil {
		t.Fatalf("sign attestDupFinal tx: %v", err)
	}
	attestDupFinalRes := post("/product/attestations?idempotent=true", attestDupFinal)
	if attestDupFinalRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent finalized attest duplicate, got %d body=%s", attestDupFinalRes.Code, attestDupFinalRes.Body.String())
	}
	var attestFinalResp struct {
		OK         bool               `json:"ok"`
		Idempotent bool               `json:"idempotent"`
		Duplicate  bool               `json:"duplicate"`
		State      string             `json:"state"`
		Proof      chain.ProductProof `json:"proof"`
	}
	if err := json.NewDecoder(attestDupFinalRes.Body).Decode(&attestFinalResp); err != nil {
		t.Fatalf("decode attest finalized idempotent response: %v", err)
	}
	if !attestFinalResp.OK || !attestFinalResp.Idempotent || !attestFinalResp.Duplicate || attestFinalResp.State != chain.TxStateFinalized {
		t.Fatalf("unexpected attest finalized idempotent response: %+v", attestFinalResp)
	}
	if attestFinalResp.Proof.ProofRef != "idem-proof-ref" {
		t.Fatalf("unexpected proof in attest finalized idempotent response: %+v", attestFinalResp.Proof)
	}

	proofs := c.GetProductProofs()
	if len(proofs) != 1 {
		t.Fatalf("expected one proof after attestation finalization, got %d", len(proofs))
	}
	proofID := proofs[0].ID

	challenge1 := chain.Transaction{
		Kind:      chain.TxKindProductChallenge,
		From:      aliceAddr,
		To:        chain.Address(proofID),
		Amount:    15,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_600_010,
	}
	if err := chain.SignTransaction(&challenge1, alicePriv); err != nil {
		t.Fatalf("sign challenge1 tx: %v", err)
	}
	challenge1Res := post("/product/challenges", challenge1)
	if challenge1Res.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for challenge1 submit, got %d body=%s", challenge1Res.Code, challenge1Res.Body.String())
	}

	challengeDupPending := chain.Transaction{
		Kind:      chain.TxKindProductChallenge,
		From:      aliceAddr,
		To:        chain.Address(proofID),
		Amount:    15,
		Fee:       1,
		Nonce:     2,
		Timestamp: 1_700_000_600_011,
	}
	if err := chain.SignTransaction(&challengeDupPending, alicePriv); err != nil {
		t.Fatalf("sign challengeDupPending tx: %v", err)
	}
	challengeDupNoIdemRes := post("/product/challenges", challengeDupPending)
	if challengeDupNoIdemRes.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate pending challenge without idempotent flag, got %d body=%s", challengeDupNoIdemRes.Code, challengeDupNoIdemRes.Body.String())
	}
	challengeDupPendingRes := post("/product/challenges?idempotent=true", challengeDupPending)
	if challengeDupPendingRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent pending challenge duplicate, got %d body=%s", challengeDupPendingRes.Code, challengeDupPendingRes.Body.String())
	}
	var challengePendingResp struct {
		OK         bool   `json:"ok"`
		Idempotent bool   `json:"idempotent"`
		Duplicate  bool   `json:"duplicate"`
		State      string `json:"state"`
		TxID       string `json:"txId"`
	}
	if err := json.NewDecoder(challengeDupPendingRes.Body).Decode(&challengePendingResp); err != nil {
		t.Fatalf("decode challenge pending idempotent response: %v", err)
	}
	if !challengePendingResp.OK || !challengePendingResp.Idempotent || !challengePendingResp.Duplicate || challengePendingResp.State != chain.TxStatePending || challengePendingResp.TxID == "" {
		t.Fatalf("unexpected challenge pending idempotent response: %+v", challengePendingResp)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce challenge block: %v", err)
	}

	challengeDupFinal := chain.Transaction{
		Kind:      chain.TxKindProductChallenge,
		From:      aliceAddr,
		To:        chain.Address(proofID),
		Amount:    15,
		Fee:       1,
		Nonce:     2,
		Timestamp: 1_700_000_600_012,
	}
	if err := chain.SignTransaction(&challengeDupFinal, alicePriv); err != nil {
		t.Fatalf("sign challengeDupFinal tx: %v", err)
	}
	challengeDupFinalRes := post("/product/challenges?idempotent=true", challengeDupFinal)
	if challengeDupFinalRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent finalized challenge duplicate, got %d body=%s", challengeDupFinalRes.Code, challengeDupFinalRes.Body.String())
	}
	var challengeFinalResp struct {
		OK         bool                   `json:"ok"`
		Idempotent bool                   `json:"idempotent"`
		Duplicate  bool                   `json:"duplicate"`
		State      string                 `json:"state"`
		Challenge  chain.ProductChallenge `json:"challenge"`
	}
	if err := json.NewDecoder(challengeDupFinalRes.Body).Decode(&challengeFinalResp); err != nil {
		t.Fatalf("decode challenge finalized idempotent response: %v", err)
	}
	if !challengeFinalResp.OK || !challengeFinalResp.Idempotent || !challengeFinalResp.Duplicate || challengeFinalResp.State != chain.TxStatePending {
		t.Fatalf("unexpected challenge finalized idempotent response: %+v", challengeFinalResp)
	}
	if !challengeFinalResp.Challenge.Open || challengeFinalResp.Challenge.ProofID != proofID {
		t.Fatalf("unexpected challenge in idempotent response: %+v", challengeFinalResp.Challenge)
	}
	challengeID := challengeFinalResp.Challenge.ID

	resolve1 := chain.Transaction{
		Kind:        chain.TxKindProductResolveChallenge,
		To:          chain.Address(challengeID),
		Amount:      0,
		Fee:         1,
		Nonce:       2,
		Timestamp:   1_700_000_600_020,
		BasisPoints: 0,
	}
	if err := chain.SignTransaction(&resolve1, valPriv); err != nil {
		t.Fatalf("sign resolve1 tx: %v", err)
	}
	resolve1Res := post("/product/challenges/resolve", resolve1)
	if resolve1Res.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for resolve1 submit, got %d body=%s", resolve1Res.Code, resolve1Res.Body.String())
	}

	resolveDupPending := chain.Transaction{
		Kind:        chain.TxKindProductResolveChallenge,
		To:          chain.Address(challengeID),
		Amount:      0,
		Fee:         1,
		Nonce:       3,
		Timestamp:   1_700_000_600_021,
		BasisPoints: 0,
	}
	if err := chain.SignTransaction(&resolveDupPending, valPriv); err != nil {
		t.Fatalf("sign resolveDupPending tx: %v", err)
	}
	resolveDupNoIdemRes := post("/product/challenges/resolve", resolveDupPending)
	if resolveDupNoIdemRes.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate pending resolve without idempotent flag, got %d body=%s", resolveDupNoIdemRes.Code, resolveDupNoIdemRes.Body.String())
	}
	resolveDupPendingRes := post("/product/challenges/resolve?idempotent=true", resolveDupPending)
	if resolveDupPendingRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent pending resolve duplicate, got %d body=%s", resolveDupPendingRes.Code, resolveDupPendingRes.Body.String())
	}
	var resolvePendingResp struct {
		OK         bool   `json:"ok"`
		Idempotent bool   `json:"idempotent"`
		Duplicate  bool   `json:"duplicate"`
		State      string `json:"state"`
		TxID       string `json:"txId"`
	}
	if err := json.NewDecoder(resolveDupPendingRes.Body).Decode(&resolvePendingResp); err != nil {
		t.Fatalf("decode resolve pending idempotent response: %v", err)
	}
	if !resolvePendingResp.OK || !resolvePendingResp.Idempotent || !resolvePendingResp.Duplicate || resolvePendingResp.State != chain.TxStatePending || resolvePendingResp.TxID == "" {
		t.Fatalf("unexpected resolve pending idempotent response: %+v", resolvePendingResp)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce resolve block: %v", err)
	}

	resolveDupFinal := chain.Transaction{
		Kind:        chain.TxKindProductResolveChallenge,
		To:          chain.Address(challengeID),
		Amount:      0,
		Fee:         1,
		Nonce:       3,
		Timestamp:   1_700_000_600_022,
		BasisPoints: 0,
	}
	if err := chain.SignTransaction(&resolveDupFinal, valPriv); err != nil {
		t.Fatalf("sign resolveDupFinal tx: %v", err)
	}
	resolveDupFinalRes := post("/product/challenges/resolve?idempotent=true", resolveDupFinal)
	if resolveDupFinalRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent finalized resolve duplicate, got %d body=%s", resolveDupFinalRes.Code, resolveDupFinalRes.Body.String())
	}
	var resolveFinalResp struct {
		OK         bool                   `json:"ok"`
		Idempotent bool                   `json:"idempotent"`
		Duplicate  bool                   `json:"duplicate"`
		State      string                 `json:"state"`
		Challenge  chain.ProductChallenge `json:"challenge"`
	}
	if err := json.NewDecoder(resolveDupFinalRes.Body).Decode(&resolveFinalResp); err != nil {
		t.Fatalf("decode resolve finalized idempotent response: %v", err)
	}
	if !resolveFinalResp.OK || !resolveFinalResp.Idempotent || !resolveFinalResp.Duplicate || resolveFinalResp.State != chain.TxStateFinalized {
		t.Fatalf("unexpected resolve finalized idempotent response: %+v", resolveFinalResp)
	}
	if resolveFinalResp.Challenge.Open {
		t.Fatalf("expected resolved challenge to be closed in idempotent response")
	}
}

func TestTxLookupEndpoint(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	validators := c.GetValidators()
	if len(validators) == 0 {
		t.Fatalf("expected at least one validator")
	}

	tx := chain.Transaction{
		From:      aliceAddr,
		To:        validators[0].Address,
		Amount:    10,
		Fee:       1,
		Nonce:     1,
		Timestamp: time.Now().UnixMilli(),
	}
	if err := chain.SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	txID, err := c.SubmitTx(tx)
	if err != nil {
		t.Fatalf("submit tx: %v", err)
	}

	pendingReq := httptest.NewRequest(http.MethodGet, "/tx?id="+txID, nil)
	pendingRes := httptest.NewRecorder()
	srv.ServeHTTP(pendingRes, pendingReq)
	if pendingRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for pending tx lookup, got %d", pendingRes.Code)
	}
	var pendingLookup chain.TransactionLookup
	if err := json.NewDecoder(pendingRes.Body).Decode(&pendingLookup); err != nil {
		t.Fatalf("decode pending tx lookup: %v", err)
	}
	if pendingLookup.State != chain.TxStatePending {
		t.Fatalf("expected tx state pending, got %q", pendingLookup.State)
	}
	if pendingLookup.MempoolIndex == nil {
		t.Fatalf("expected mempool index for pending tx")
	}
	if pendingLookup.Finalized != nil {
		t.Fatalf("expected no finalized metadata for pending tx")
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}

	finalizedReq := httptest.NewRequest(http.MethodGet, "/tx?id="+txID, nil)
	finalizedRes := httptest.NewRecorder()
	srv.ServeHTTP(finalizedRes, finalizedReq)
	if finalizedRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for finalized tx lookup, got %d", finalizedRes.Code)
	}
	var finalizedLookup chain.TransactionLookup
	if err := json.NewDecoder(finalizedRes.Body).Decode(&finalizedLookup); err != nil {
		t.Fatalf("decode finalized tx lookup: %v", err)
	}
	if finalizedLookup.State != chain.TxStateFinalized {
		t.Fatalf("expected tx state finalized, got %q", finalizedLookup.State)
	}
	if finalizedLookup.Finalized == nil {
		t.Fatalf("expected finalized metadata")
	}
	if finalizedLookup.Finalized.Height == 0 {
		t.Fatalf("expected finalized height > 0")
	}
	if finalizedLookup.MempoolIndex != nil {
		t.Fatalf("expected no mempool index for finalized tx")
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/tx?id=missing", nil)
	missingRes := httptest.NewRecorder()
	srv.ServeHTTP(missingRes, missingReq)
	if missingRes.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown tx id, got %d", missingRes.Code)
	}
}

func TestSubmitTxIdempotentRetries(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	validators := c.GetValidators()
	if len(validators) == 0 {
		t.Fatalf("expected at least one validator")
	}

	tx := chain.Transaction{
		From:      aliceAddr,
		To:        validators[0].Address,
		Amount:    10,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_400_001,
	}
	if err := chain.SignTransaction(&tx, alicePriv); err != nil {
		t.Fatalf("sign tx: %v", err)
	}

	body, _ := json.Marshal(tx)
	firstReq := httptest.NewRequest(http.MethodPost, "/tx", bytes.NewReader(body))
	firstReq.Header.Set("Content-Type", "application/json")
	firstRes := httptest.NewRecorder()
	srv.ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for first tx submission, got %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	dupReq := httptest.NewRequest(http.MethodPost, "/tx", bytes.NewReader(body))
	dupReq.Header.Set("Content-Type", "application/json")
	dupRes := httptest.NewRecorder()
	srv.ServeHTTP(dupRes, dupReq)
	if dupRes.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate tx without idempotent flag, got %d body=%s", dupRes.Code, dupRes.Body.String())
	}

	idemReq := httptest.NewRequest(http.MethodPost, "/tx?idempotent=true", bytes.NewReader(body))
	idemReq.Header.Set("Content-Type", "application/json")
	idemRes := httptest.NewRecorder()
	srv.ServeHTTP(idemRes, idemReq)
	if idemRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent duplicate tx, got %d body=%s", idemRes.Code, idemRes.Body.String())
	}
	var idemResp struct {
		OK         bool   `json:"ok"`
		Idempotent bool   `json:"idempotent"`
		Duplicate  bool   `json:"duplicate"`
		TxID       string `json:"txId"`
		State      string `json:"state"`
	}
	if err := json.NewDecoder(idemRes.Body).Decode(&idemResp); err != nil {
		t.Fatalf("decode idempotent duplicate response: %v", err)
	}
	if !idemResp.OK || !idemResp.Idempotent || !idemResp.Duplicate || idemResp.State != chain.TxStatePending {
		t.Fatalf("unexpected idempotent pending duplicate response: %+v", idemResp)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}

	idemFinalReq := httptest.NewRequest(http.MethodPost, "/tx?idempotent=true", bytes.NewReader(body))
	idemFinalReq.Header.Set("Content-Type", "application/json")
	idemFinalRes := httptest.NewRecorder()
	srv.ServeHTTP(idemFinalRes, idemFinalReq)
	if idemFinalRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent finalized duplicate tx, got %d body=%s", idemFinalRes.Code, idemFinalRes.Body.String())
	}
	var idemFinalResp struct {
		OK         bool   `json:"ok"`
		Idempotent bool   `json:"idempotent"`
		Duplicate  bool   `json:"duplicate"`
		TxID       string `json:"txId"`
		State      string `json:"state"`
	}
	if err := json.NewDecoder(idemFinalRes.Body).Decode(&idemFinalResp); err != nil {
		t.Fatalf("decode idempotent finalized response: %v", err)
	}
	if !idemFinalResp.OK || !idemFinalResp.Idempotent || !idemFinalResp.Duplicate || idemFinalResp.State != chain.TxStateFinalized {
		t.Fatalf("unexpected idempotent finalized duplicate response: %+v", idemFinalResp)
	}
}

func TestPendingTxEndpointFiltersAndPagination(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, valPriv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	validators := c.GetValidators()
	if len(validators) != 1 {
		t.Fatalf("expected one validator in test chain")
	}

	tx1 := chain.Transaction{
		From:      aliceAddr,
		To:        validators[0].Address,
		Amount:    10,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_200_001,
	}
	if err := chain.SignTransaction(&tx1, alicePriv); err != nil {
		t.Fatalf("sign tx1: %v", err)
	}
	if _, err := c.SubmitTx(tx1); err != nil {
		t.Fatalf("submit tx1: %v", err)
	}

	tx2 := chain.Transaction{
		From:      aliceAddr,
		To:        validators[0].Address,
		Amount:    11,
		Fee:       2,
		Nonce:     2,
		Timestamp: 1_700_000_200_002,
	}
	if err := chain.SignTransaction(&tx2, alicePriv); err != nil {
		t.Fatalf("sign tx2: %v", err)
	}
	if _, err := c.SubmitTx(tx2); err != nil {
		t.Fatalf("submit tx2: %v", err)
	}

	tx3 := chain.Transaction{
		Kind:        chain.TxKindValidatorBond,
		Amount:      15,
		Fee:         3,
		Nonce:       1,
		Timestamp:   1_700_000_200_003,
		ValidatorID: validators[0].ID,
	}
	if err := chain.SignTransaction(&tx3, valPriv); err != nil {
		t.Fatalf("sign tx3: %v", err)
	}
	if _, err := c.SubmitTx(tx3); err != nil {
		t.Fatalf("submit tx3: %v", err)
	}

	assertPending := func(path string, expected int) []chain.PendingTransaction {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d body=%s", path, res.Code, res.Body.String())
		}
		var out []chain.PendingTransaction
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatalf("decode pending tx response for %s: %v", path, err)
		}
		if len(out) != expected {
			t.Fatalf("expected %d pending txs for %s, got %d", expected, path, len(out))
		}
		return out
	}

	assertPending("/tx/pending", 3)
	assertPending("/tx/pending?from="+string(aliceAddr), 2)
	assertPending("/tx/pending?kind="+chain.TxKindTransfer, 2)
	assertPending("/tx/pending?kind="+chain.TxKindValidatorBond+"&validatorId="+validators[0].ID, 1)
	assertPending("/tx/pending?minFee=2", 2)
	assertPending("/tx/pending?maxFee=1", 1)
	assertPending("/tx/pending?limit=1", 1)
	assertPending("/tx/pending?offset=1&limit=1", 1)
	assertPending("/tx/pending?offset=5&limit=1", 0)

	metaReq := httptest.NewRequest(http.MethodGet, "/tx/pending?kind="+chain.TxKindTransfer+"&limit=1&withMeta=true", nil)
	metaRes := httptest.NewRecorder()
	srv.ServeHTTP(metaRes, metaReq)
	if metaRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for pending tx metadata response, got %d", metaRes.Code)
	}
	var metaPayload struct {
		Items   []chain.PendingTransaction `json:"items"`
		Total   int                        `json:"total"`
		Offset  int                        `json:"offset"`
		Limit   int                        `json:"limit"`
		Count   int                        `json:"count"`
		HasMore bool                       `json:"hasMore"`
	}
	if err := json.NewDecoder(metaRes.Body).Decode(&metaPayload); err != nil {
		t.Fatalf("decode pending tx metadata response: %v", err)
	}
	if metaPayload.Total != 2 || metaPayload.Count != 1 || !metaPayload.HasMore {
		t.Fatalf("unexpected pending tx metadata payload: %+v", metaPayload)
	}

	badQueryReq := httptest.NewRequest(http.MethodGet, "/tx/pending?minFee=bad", nil)
	badQueryRes := httptest.NewRecorder()
	srv.ServeHTTP(badQueryRes, badQueryReq)
	if badQueryRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad pending tx query, got %d", badQueryRes.Code)
	}
	badWithMetaReq := httptest.NewRequest(http.MethodGet, "/tx/pending?withMeta=bad", nil)
	badWithMetaRes := httptest.NewRecorder()
	srv.ServeHTTP(badWithMetaRes, badWithMetaReq)
	if badWithMetaRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad pending tx withMeta query, got %d", badWithMetaRes.Code)
	}
	badOffsetReq := httptest.NewRequest(http.MethodGet, "/tx/pending?offset=bad", nil)
	badOffsetRes := httptest.NewRecorder()
	srv.ServeHTTP(badOffsetRes, badOffsetReq)
	if badOffsetRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad pending tx offset query, got %d", badOffsetRes.Code)
	}
	negativeLimitReq := httptest.NewRequest(http.MethodGet, "/tx/pending?limit=-1", nil)
	negativeLimitRes := httptest.NewRecorder()
	srv.ServeHTTP(negativeLimitRes, negativeLimitReq)
	if negativeLimitRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative pending tx limit query, got %d", negativeLimitRes.Code)
	}
}

func TestFinalizedTxEndpointFiltersAndPagination(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	_, alicePriv, aliceAddr, err := chain.DeterministicKeypair("alice-test-node")
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	_, valPriv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}
	validators := c.GetValidators()
	if len(validators) != 1 {
		t.Fatalf("expected one validator in test chain")
	}

	tx1 := chain.Transaction{
		From:      aliceAddr,
		To:        validators[0].Address,
		Amount:    10,
		Fee:       1,
		Nonce:     1,
		Timestamp: 1_700_000_300_001,
	}
	if err := chain.SignTransaction(&tx1, alicePriv); err != nil {
		t.Fatalf("sign tx1: %v", err)
	}
	if _, err := c.SubmitTx(tx1); err != nil {
		t.Fatalf("submit tx1: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block for tx1: %v", err)
	}

	tx2 := chain.Transaction{
		From:      aliceAddr,
		To:        validators[0].Address,
		Amount:    11,
		Fee:       2,
		Nonce:     2,
		Timestamp: 1_700_000_300_002,
	}
	if err := chain.SignTransaction(&tx2, alicePriv); err != nil {
		t.Fatalf("sign tx2: %v", err)
	}
	if _, err := c.SubmitTx(tx2); err != nil {
		t.Fatalf("submit tx2: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block for tx2: %v", err)
	}

	tx3 := chain.Transaction{
		Kind:        chain.TxKindValidatorBond,
		Amount:      15,
		Fee:         3,
		Nonce:       1,
		Timestamp:   1_700_000_300_003,
		ValidatorID: validators[0].ID,
	}
	if err := chain.SignTransaction(&tx3, valPriv); err != nil {
		t.Fatalf("sign tx3: %v", err)
	}
	if _, err := c.SubmitTx(tx3); err != nil {
		t.Fatalf("submit tx3: %v", err)
	}
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block for tx3: %v", err)
	}

	assertFinalized := func(path string, expected int) []chain.TransactionLookup {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		srv.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d body=%s", path, res.Code, res.Body.String())
		}
		var out []chain.TransactionLookup
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatalf("decode finalized tx response for %s: %v", path, err)
		}
		if len(out) != expected {
			t.Fatalf("expected %d finalized txs for %s, got %d", expected, path, len(out))
		}
		return out
	}

	all := assertFinalized("/tx/finalized", 3)
	if all[0].Finalized == nil || all[0].Finalized.Height == 0 {
		t.Fatalf("expected finalized metadata in list response")
	}
	assertFinalized("/tx/finalized?from="+string(aliceAddr), 2)
	assertFinalized("/tx/finalized?kind="+chain.TxKindTransfer, 2)
	assertFinalized("/tx/finalized?kind="+chain.TxKindValidatorBond+"&validatorId="+validators[0].ID, 1)
	assertFinalized("/tx/finalized?minFee=2", 2)
	assertFinalized("/tx/finalized?maxFee=1", 1)
	assertFinalized("/tx/finalized?minHeight=2", 2)
	assertFinalized("/tx/finalized?maxHeight=2", 2)
	assertFinalized("/tx/finalized?limit=1", 1)
	assertFinalized("/tx/finalized?offset=1&limit=1", 1)
	assertFinalized("/tx/finalized?offset=5&limit=1", 0)

	metaReq := httptest.NewRequest(http.MethodGet, "/tx/finalized?kind="+chain.TxKindTransfer+"&limit=1&withMeta=true", nil)
	metaRes := httptest.NewRecorder()
	srv.ServeHTTP(metaRes, metaReq)
	if metaRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for finalized tx metadata response, got %d", metaRes.Code)
	}
	var metaPayload struct {
		Items   []chain.TransactionLookup `json:"items"`
		Total   int                       `json:"total"`
		Offset  int                       `json:"offset"`
		Limit   int                       `json:"limit"`
		Count   int                       `json:"count"`
		HasMore bool                      `json:"hasMore"`
	}
	if err := json.NewDecoder(metaRes.Body).Decode(&metaPayload); err != nil {
		t.Fatalf("decode finalized tx metadata response: %v", err)
	}
	if metaPayload.Total != 2 || metaPayload.Count != 1 || !metaPayload.HasMore {
		t.Fatalf("unexpected finalized tx metadata payload: %+v", metaPayload)
	}

	badQueryReq := httptest.NewRequest(http.MethodGet, "/tx/finalized?minHeight=bad", nil)
	badQueryRes := httptest.NewRecorder()
	srv.ServeHTTP(badQueryRes, badQueryReq)
	if badQueryRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad finalized tx query, got %d", badQueryRes.Code)
	}
	badWithMetaReq := httptest.NewRequest(http.MethodGet, "/tx/finalized?withMeta=bad", nil)
	badWithMetaRes := httptest.NewRecorder()
	srv.ServeHTTP(badWithMetaRes, badWithMetaReq)
	if badWithMetaRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad finalized tx withMeta query, got %d", badWithMetaRes.Code)
	}
	badOffsetReq := httptest.NewRequest(http.MethodGet, "/tx/finalized?offset=bad", nil)
	badOffsetRes := httptest.NewRecorder()
	srv.ServeHTTP(badOffsetRes, badOffsetReq)
	if badOffsetRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad finalized tx offset query, got %d", badOffsetRes.Code)
	}
	negativeLimitReq := httptest.NewRequest(http.MethodGet, "/tx/finalized?limit=-1", nil)
	negativeLimitRes := httptest.NewRecorder()
	srv.ServeHTTP(negativeLimitRes, negativeLimitReq)
	if negativeLimitRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative finalized tx limit query, got %d", negativeLimitRes.Code)
	}
}

func TestSigningEndpointsDisabledByDefault(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{AllowDevSigning: false})

	reqWallet := httptest.NewRequest(http.MethodPost, "/wallets", nil)
	resWallet := httptest.NewRecorder()
	srv.ServeHTTP(resWallet, reqWallet)
	if resWallet.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for /wallets, got %d", resWallet.Code)
	}

	reqSignSubmit := httptest.NewRequest(http.MethodPost, "/tx/sign-and-submit", bytes.NewReader([]byte(`{"privateKey":"x","to":"y","amount":1,"fee":1}`)))
	reqSignSubmit.Header.Set("Content-Type", "application/json")
	resSignSubmit := httptest.NewRecorder()
	srv.ServeHTTP(resSignSubmit, reqSignSubmit)
	if resSignSubmit.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for /tx/sign-and-submit, got %d", resSignSubmit.Code)
	}
}

func TestSignTxSupportsValidatorBondWithoutTo(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{AllowDevSigning: true})

	_, priv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}

	payload := map[string]any{
		"privateKey":  priv,
		"kind":        chain.TxKindValidatorBond,
		"validatorId": "v1",
		"amount":      uint64(50),
		"fee":         uint64(1),
		"nonce":       uint64(1),
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/tx/sign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 for validator bond sign, got %d", res.Code)
	}

	var resp struct {
		Tx   chain.Transaction `json:"tx"`
		TxID string            `json:"txId"`
	}
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode sign response: %v", err)
	}
	if resp.Tx.Kind != chain.TxKindValidatorBond {
		t.Fatalf("expected tx kind %q, got %q", chain.TxKindValidatorBond, resp.Tx.Kind)
	}
	if resp.Tx.To != "" {
		t.Fatalf("expected empty recipient for validator bond tx, got %q", resp.Tx.To)
	}
	if resp.Tx.ValidatorID != "v1" {
		t.Fatalf("expected validator id v1, got %q", resp.Tx.ValidatorID)
	}
	if resp.TxID == "" {
		t.Fatalf("expected tx id in response")
	}
}

func TestSignAndSubmitValidatorBondTx(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{AllowDevSigning: true})

	_, priv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("validator keypair: %v", err)
	}

	payload := map[string]any{
		"privateKey":  priv,
		"kind":        chain.TxKindValidatorBond,
		"validatorId": "v1",
		"amount":      uint64(50),
		"fee":         uint64(1),
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/tx/sign-and-submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for validator bond sign-and-submit, got %d", res.Code)
	}

	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}

	validator, ok := c.GetValidator("v1")
	if !ok {
		t.Fatalf("validator v1 missing")
	}
	if validator.Stake != 1_050 {
		t.Fatalf("expected validator stake 1050, got %d", validator.Stake)
	}
	account, ok := c.GetAccount(validator.Address)
	if !ok {
		t.Fatalf("validator account missing")
	}
	if account.Balance != 950 {
		t.Fatalf("expected validator balance 950 after bond tx finalization, got %d", account.Balance)
	}
}

func TestHealthReadyAndMetricsEndpoints(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	resHealth := httptest.NewRecorder()
	srv.ServeHTTP(resHealth, reqHealth)
	if resHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 for /healthz, got %d", resHealth.Code)
	}

	reqReady := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	resReady := httptest.NewRecorder()
	srv.ServeHTTP(resReady, reqReady)
	if resReady.Code != http.StatusOK {
		t.Fatalf("expected 200 for /readyz, got %d", resReady.Code)
	}

	reqMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	resMetrics := httptest.NewRecorder()
	srv.ServeHTTP(resMetrics, reqMetrics)
	if resMetrics.Code != http.StatusOK {
		t.Fatalf("expected 200 for /metrics, got %d", resMetrics.Code)
	}
	body, err := io.ReadAll(resMetrics.Result().Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	if !strings.Contains(string(body), "fastpos_chain_height") {
		t.Fatalf("expected fastpos_chain_height metric in output, got %s", string(body))
	}
}

func TestSyncSnapshotEndpoint(t *testing.T) {
	c := newTestChain(t)
	if _, err := c.ProduceOnce(); err != nil {
		t.Fatalf("produce block: %v", err)
	}
	srv := NewServer(c, Config{})

	req := httptest.NewRequest(http.MethodGet, "/sync/snapshot", nil)
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 for /sync/snapshot, got %d", res.Code)
	}

	var snapshot chain.Snapshot
	if err := json.NewDecoder(res.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decode snapshot response: %v", err)
	}
	if snapshot.Version == 0 {
		t.Fatalf("expected snapshot version to be set")
	}
	if len(snapshot.Blocks) == 0 {
		t.Fatalf("expected snapshot to include blocks")
	}
}

func TestP2PMessageEndpoint(t *testing.T) {
	c := newTestChain(t)
	validators := c.GetValidators()
	pubByID := map[string]string{}
	for _, v := range validators {
		pubByID[v.ID] = v.PubKey
	}

	_, priv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}
	block, err := c.BuildProposal("v1")
	if err != nil {
		t.Fatalf("build proposal: %v", err)
	}
	p2pSvc, err := p2p.NewService(p2p.Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: priv,
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new p2p service: %v", err)
	}
	p2pSvc.AttachChain(c)

	srv := NewServer(c, Config{P2PService: p2pSvc})
	payload := p2p.BlockProposal{Block: block}
	env, err := p2p.NewEnvelope(p2p.MessageTypeBlockProposal, "v1", payload, priv)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	body, _ := json.Marshal(env)

	req := httptest.NewRequest(http.MethodPost, "/p2p/message", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for first message, got %d", res.Code)
	}

	reqDup := httptest.NewRequest(http.MethodPost, "/p2p/message", bytes.NewReader(body))
	reqDup.Header.Set("Content-Type", "application/json")
	resDup := httptest.NewRecorder()
	srv.ServeHTTP(resDup, reqDup)
	if resDup.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate message, got %d", resDup.Code)
	}
}

func TestP2PMessageEndpointRateLimit(t *testing.T) {
	c := newTestChain(t)
	validators := c.GetValidators()
	pubByID := map[string]string{}
	for _, v := range validators {
		pubByID[v.ID] = v.PubKey
	}

	_, priv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}
	block, err := c.BuildProposal("v1")
	if err != nil {
		t.Fatalf("build proposal: %v", err)
	}
	p2pSvc, err := p2p.NewService(p2p.Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: priv,
		ValidatorPubKeys:    pubByID,
		InboundRateLimit:    1,
		InboundRateWindow:   time.Minute,
	})
	if err != nil {
		t.Fatalf("new p2p service: %v", err)
	}
	p2pSvc.AttachChain(c)

	srv := NewServer(c, Config{P2PService: p2pSvc})
	payload := p2p.BlockProposal{Block: block}
	env, err := p2p.NewEnvelope(p2p.MessageTypeBlockProposal, "v1", payload, priv)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	body, _ := json.Marshal(env)

	req := httptest.NewRequest(http.MethodPost, "/p2p/message", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:44321"
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for first message, got %d", res.Code)
	}

	reqRateLimited := httptest.NewRequest(http.MethodPost, "/p2p/message", bytes.NewReader(body))
	reqRateLimited.Header.Set("Content-Type", "application/json")
	reqRateLimited.RemoteAddr = "203.0.113.9:44321"
	resRateLimited := httptest.NewRecorder()
	srv.ServeHTTP(resRateLimited, reqRateLimited)
	if resRateLimited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for rate-limited message, got %d", resRateLimited.Code)
	}
}

func TestP2PEvidenceEndpoints(t *testing.T) {
	c := newTestChain(t)
	validators := c.GetValidators()
	pubByID := map[string]string{}
	for _, v := range validators {
		pubByID[v.ID] = v.PubKey
	}

	_, priv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}
	block, err := c.BuildProposal("v1")
	if err != nil {
		t.Fatalf("build proposal: %v", err)
	}
	p2pSvc, err := p2p.NewService(p2p.Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: priv,
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new p2p service: %v", err)
	}
	p2pSvc.AttachChain(c)

	proposalEnv, err := p2p.NewEnvelope(p2p.MessageTypeBlockProposal, "v1", p2p.BlockProposal{Block: block}, priv)
	if err != nil {
		t.Fatalf("new proposal envelope: %v", err)
	}
	if err := p2pSvc.HandleEnvelope(proposalEnv); err != nil {
		t.Fatalf("handle proposal envelope: %v", err)
	}
	vote1 := p2p.BlockVote{
		Height:    block.Height,
		BlockHash: block.Hash,
		VoterID:   "v1",
		Approve:   true,
		Timestamp: block.Timestamp,
	}
	voteEnv1, err := p2p.NewEnvelope(p2p.MessageTypeBlockVote, "v1", vote1, priv)
	if err != nil {
		t.Fatalf("new vote envelope: %v", err)
	}
	if err := p2pSvc.HandleEnvelope(voteEnv1); err != nil {
		t.Fatalf("handle vote envelope: %v", err)
	}
	vote2 := vote1
	vote2.BlockHash = "conflicting-hash"
	voteEnv2, err := p2p.NewEnvelope(p2p.MessageTypeBlockVote, "v1", vote2, priv)
	if err != nil {
		t.Fatalf("new conflicting vote envelope: %v", err)
	}
	if err := p2pSvc.HandleEnvelope(voteEnv2); err == nil {
		t.Fatalf("expected conflicting vote error")
	}

	srv := NewServer(c, Config{
		AdminToken: "secret",
		P2PService: p2pSvc,
	})

	getReq := httptest.NewRequest(http.MethodGet, "/p2p/evidence", nil)
	getRes := httptest.NewRecorder()
	srv.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /p2p/evidence, got %d", getRes.Code)
	}
	var listResp struct {
		Enabled  bool                       `json:"enabled"`
		Evidence []p2p.EquivocationEvidence `json:"evidence"`
	}
	if err := json.NewDecoder(getRes.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode evidence list response: %v", err)
	}
	if !listResp.Enabled {
		t.Fatalf("expected evidence endpoint to report enabled=true")
	}
	if len(listResp.Evidence) != 1 {
		t.Fatalf("expected 1 evidence entry, got %d", len(listResp.Evidence))
	}

	applyPayload := map[string]any{
		"evidenceId":  listResp.Evidence[0].ID,
		"basisPoints": uint64(1_000),
	}
	applyBody, _ := json.Marshal(applyPayload)
	applyReq := httptest.NewRequest(http.MethodPost, "/p2p/evidence", bytes.NewReader(applyBody))
	applyReq.Header.Set("Content-Type", "application/json")
	applyReq.Header.Set("X-Admin-Token", "secret")
	applyRes := httptest.NewRecorder()
	srv.ServeHTTP(applyRes, applyReq)
	if applyRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for /p2p/evidence apply, got %d", applyRes.Code)
	}

	validator, ok := c.GetValidator("v1")
	if !ok {
		t.Fatalf("expected validator v1 to exist")
	}
	if !validator.Jailed {
		t.Fatalf("expected validator v1 to be jailed after evidence penalty")
	}
}

func TestP2PMessageEndpointDisabled(t *testing.T) {
	c := newTestChain(t)
	srv := NewServer(c, Config{})

	req := httptest.NewRequest(http.MethodPost, "/p2p/message", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when p2p is disabled, got %d", res.Code)
	}
}

func TestP2PPeerManagementEndpoint(t *testing.T) {
	c := newTestChain(t)
	validators := c.GetValidators()
	pubByID := map[string]string{}
	for _, v := range validators {
		pubByID[v.ID] = v.PubKey
	}

	_, priv, _, err := chain.DeterministicKeypair("validator-test")
	if err != nil {
		t.Fatalf("deterministic keypair: %v", err)
	}
	p2pSvc, err := p2p.NewService(p2p.Config{
		Enabled:             true,
		NodeID:              "v1",
		ValidatorPrivateKey: priv,
		ValidatorPubKeys:    pubByID,
	})
	if err != nil {
		t.Fatalf("new p2p service: %v", err)
	}

	srv := NewServer(c, Config{
		AdminToken: "secret",
		P2PService: p2pSvc,
	})

	getReq := httptest.NewRequest(http.MethodGet, "/p2p/peers", nil)
	getRes := httptest.NewRecorder()
	srv.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for initial GET /p2p/peers, got %d", getRes.Code)
	}

	addBody := []byte(`{"url":"http://127.0.0.1:19082/"}`)
	addReqNoAuth := httptest.NewRequest(http.MethodPost, "/p2p/peers", bytes.NewReader(addBody))
	addReqNoAuth.Header.Set("Content-Type", "application/json")
	addResNoAuth := httptest.NewRecorder()
	srv.ServeHTTP(addResNoAuth, addReqNoAuth)
	if addResNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST /p2p/peers, got %d", addResNoAuth.Code)
	}

	addReq := httptest.NewRequest(http.MethodPost, "/p2p/peers", bytes.NewReader(addBody))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("X-Admin-Token", "secret")
	addRes := httptest.NewRecorder()
	srv.ServeHTTP(addRes, addReq)
	if addRes.Code != http.StatusCreated {
		t.Fatalf("expected 201 for first POST /p2p/peers, got %d", addRes.Code)
	}

	addReqDup := httptest.NewRequest(http.MethodPost, "/p2p/peers", bytes.NewReader(addBody))
	addReqDup.Header.Set("Content-Type", "application/json")
	addReqDup.Header.Set("X-Admin-Token", "secret")
	addResDup := httptest.NewRecorder()
	srv.ServeHTTP(addResDup, addReqDup)
	if addResDup.Code != http.StatusOK {
		t.Fatalf("expected 200 for duplicate POST /p2p/peers, got %d", addResDup.Code)
	}

	peers := p2pSvc.Peers()
	if len(peers) != 1 || peers[0] != "http://127.0.0.1:19082" {
		t.Fatalf("unexpected peer list after add: %+v", peers)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/p2p/peers?url=http://127.0.0.1:19082", nil)
	delReq.Header.Set("X-Admin-Token", "secret")
	delRes := httptest.NewRecorder()
	srv.ServeHTTP(delRes, delReq)
	if delRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for DELETE /p2p/peers, got %d", delRes.Code)
	}

	if len(p2pSvc.Peers()) != 0 {
		t.Fatalf("expected empty peer list after delete, got %+v", p2pSvc.Peers())
	}
}
