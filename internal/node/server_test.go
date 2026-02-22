package node

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
