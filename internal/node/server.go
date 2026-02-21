package node

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fastpos/internal/chain"
)

type Server struct {
	chain           *chain.Chain
	mux             *http.ServeMux
	adminToken      string
	allowDevSigning bool
	readinessMaxLag time.Duration
}

type Config struct {
	AdminToken      string
	AllowDevSigning bool
	ReadinessMaxLag time.Duration
}

func NewServer(c *chain.Chain, cfg Config) *Server {
	readinessLag := cfg.ReadinessMaxLag
	if readinessLag <= 0 {
		interval := c.BlockInterval()
		if interval <= 0 {
			interval = 2 * time.Second
		}
		readinessLag = interval * 4
		if readinessLag < 10*time.Second {
			readinessLag = 10 * time.Second
		}
	}

	s := &Server{
		chain:           c,
		mux:             http.NewServeMux(),
		adminToken:      cfg.AdminToken,
		allowDevSigning: cfg.AllowDevSigning,
		readinessMaxLag: readinessLag,
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/metrics.json", s.handleMetricsJSON)
	s.mux.HandleFunc("/status", s.handleStatus)
	s.mux.HandleFunc("/validators", s.handleValidators)
	s.mux.HandleFunc("/validators/work-weight", s.handleSetWorkWeight)
	s.mux.HandleFunc("/validators/active", s.handleSetActive)
	s.mux.HandleFunc("/accounts/", s.handleAccount)
	s.mux.HandleFunc("/nonce/", s.handleNonce)
	s.mux.HandleFunc("/blocks", s.handleBlocks)
	s.mux.HandleFunc("/tx", s.handleSubmitTx)
	s.mux.HandleFunc("/tx/sign", s.handleSignTx)
	s.mux.HandleFunc("/tx/sign-and-submit", s.handleSignAndSubmit)
	s.mux.HandleFunc("/wallets", s.handleWalletNew)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	metrics := s.chain.GetMetrics()
	lag := time.Since(time.UnixMilli(metrics.LastFinalizedMs))
	ready := true
	reason := "ok"

	if metrics.ActiveValidatorsCount == 0 {
		ready = false
		reason = "no active validators"
	} else if lag > s.readinessMaxLag {
		ready = false
		reason = fmt.Sprintf("finality lag %s exceeds threshold %s", lag.Round(time.Millisecond), s.readinessMaxLag)
	}

	resp := map[string]any{
		"ready":            ready,
		"reason":           reason,
		"height":           metrics.Height,
		"activeValidators": metrics.ActiveValidatorsCount,
		"lastFinalizedMs":  metrics.LastFinalizedMs,
		"maxFinalityLagMs": s.readinessMaxLag.Milliseconds(),
	}
	if ready {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	m := s.chain.GetMetrics()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# HELP fastpos_chain_height Latest finalized block height\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_chain_height gauge\n")
	_, _ = fmt.Fprintf(w, "fastpos_chain_height %d\n", m.Height)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_mempool_size Current mempool size\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_mempool_size gauge\n")
	_, _ = fmt.Fprintf(w, "fastpos_mempool_size %d\n", m.MempoolSize)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_mempool_peak Peak mempool size\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_mempool_peak gauge\n")
	_, _ = fmt.Fprintf(w, "fastpos_mempool_peak %d\n", m.MempoolPeak)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_active_validators Active validators with non-zero effective stake\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_active_validators gauge\n")
	_, _ = fmt.Fprintf(w, "fastpos_active_validators %d\n", m.ActiveValidatorsCount)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_submitted_txs_total Accepted transactions\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_submitted_txs_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_submitted_txs_total %d\n", m.SubmittedTxTotal)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_rejected_txs_total Rejected transactions\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_rejected_txs_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_rejected_txs_total %d\n", m.RejectedTxTotal)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_evicted_txs_total Evicted transactions due to mempool pressure\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_evicted_txs_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_evicted_txs_total %d\n", m.EvictedTxTotal)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_included_txs_total Transactions included in finalized blocks\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_included_txs_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_included_txs_total %d\n", m.IncludedTxTotal)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_finalized_blocks_total Finalized blocks\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_finalized_blocks_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_finalized_blocks_total %d\n", m.FinalizedBlocksTotal)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_failed_produce_total Failed block production attempts\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_failed_produce_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_failed_produce_total %d\n", m.FailedProduceTotal)
	_, _ = fmt.Fprintf(w, "# HELP fastpos_fees_collected_total Total fees collected by proposers\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_fees_collected_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_fees_collected_total %d\n", m.TotalFeesCollected)
}

func (s *Server) handleMetricsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.chain.GetMetrics())
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.chain.GetStatus())
}

func (s *Server) handleValidators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.chain.GetValidators())
}

func (s *Server) handleSetWorkWeight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		ID         string `json:"id"`
		WorkWeight uint64 `json:"workWeight"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing id"))
		return
	}
	if err := s.chain.SetValidatorWorkWeight(req.ID, req.WorkWeight); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetActive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing id"))
		return
	}
	if err := s.chain.SetValidatorActive(req.ID, req.Active); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	addr := strings.TrimPrefix(r.URL.Path, "/accounts/")
	if addr == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing account address"))
		return
	}
	acc, ok := s.chain.GetAccount(chain.Address(addr))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("account %s not found", addr))
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	addr := strings.TrimPrefix(r.URL.Path, "/nonce/")
	if addr == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing account address"))
		return
	}
	nonce, err := s.chain.NextNonce(chain.Address(addr))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]uint64{"nextNonce": nonce})
}

func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	from := queryInt(r, "from", 0)
	limit := queryInt(r, "limit", 20)
	blocks := s.chain.GetBlocks(from, limit)
	writeJSON(w, http.StatusOK, blocks)
}

func (s *Server) handleSubmitTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var tx chain.Transaction
	if err := decodeJSON(r, &tx); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	txID, err := s.chain.SubmitTx(tx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"txId": txID})
}

func (s *Server) handleWalletNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.allowDevSigning {
		writeError(w, http.StatusForbidden, errors.New("wallet generation endpoint is disabled"))
		return
	}
	pub, priv, address, err := chain.GenerateKeypair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"address":    string(address),
		"pubKey":     pub,
		"privateKey": priv,
	})
}

func (s *Server) handleSignTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.allowDevSigning {
		writeError(w, http.StatusForbidden, errors.New("tx signing endpoint is disabled"))
		return
	}
	var req struct {
		PrivateKey string        `json:"privateKey"`
		To         chain.Address `json:"to"`
		Amount     uint64        `json:"amount"`
		Fee        uint64        `json:"fee"`
		Nonce      uint64        `json:"nonce"`
		Timestamp  int64         `json:"timestamp"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.PrivateKey == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing privateKey"))
		return
	}
	if req.To == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing to"))
		return
	}

	_, addr, err := chain.PublicAndAddressFromPrivateKeyHex(req.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Nonce == 0 {
		nonce, err := s.chain.NextNonce(addr)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req.Nonce = nonce
	}

	tx := chain.Transaction{
		From:      addr,
		To:        req.To,
		Amount:    req.Amount,
		Fee:       req.Fee,
		Nonce:     req.Nonce,
		Timestamp: req.Timestamp,
	}
	if err := chain.SignTransaction(&tx, req.PrivateKey); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tx":   tx,
		"txId": tx.ID(),
	})
}

func (s *Server) handleSignAndSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.allowDevSigning {
		writeError(w, http.StatusForbidden, errors.New("sign-and-submit endpoint is disabled"))
		return
	}
	var req struct {
		PrivateKey string        `json:"privateKey"`
		To         chain.Address `json:"to"`
		Amount     uint64        `json:"amount"`
		Fee        uint64        `json:"fee"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.PrivateKey == "" || req.To == "" {
		writeError(w, http.StatusBadRequest, errors.New("privateKey and to are required"))
		return
	}

	_, from, err := chain.PublicAndAddressFromPrivateKeyHex(req.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nonce, err := s.chain.NextNonce(from)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	tx := chain.Transaction{
		From:   from,
		To:     req.To,
		Amount: req.Amount,
		Fee:    req.Fee,
		Nonce:  nonce,
	}
	if err := chain.SignTransaction(&tx, req.PrivateKey); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	txID, err := s.chain.SubmitTx(tx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"tx":   tx,
		"txId": txID,
	})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.adminToken == "" {
		return true
	}
	provided := r.Header.Get("X-Admin-Token")
	if provided == "" {
		writeError(w, http.StatusUnauthorized, errors.New("missing admin token"))
		return false
	}
	if subtle.ConstantTimeCompare([]byte(provided), []byte(s.adminToken)) != 1 {
		writeError(w, http.StatusUnauthorized, errors.New("invalid admin token"))
		return false
	}
	return true
}

func queryInt(r *http.Request, key string, defaultValue int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return defaultValue
	}
	return value
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
