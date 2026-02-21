package node

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fastpos/internal/chain"
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
			valAddr:   0,
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
