package node

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fastpos/internal/chain"
	"fastpos/internal/p2p"
)

type Server struct {
	chain            *chain.Chain
	p2p              *p2p.Service
	mux              *http.ServeMux
	adminToken       string
	allowDevSigning  bool
	readinessMaxLag  time.Duration
	productUnitPrice uint64
}

type Config struct {
	AdminToken       string
	AllowDevSigning  bool
	ReadinessMaxLag  time.Duration
	ProductUnitPrice uint64
	P2PService       *p2p.Service
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
		chain:            c,
		p2p:              cfg.P2PService,
		mux:              http.NewServeMux(),
		adminToken:       cfg.AdminToken,
		allowDevSigning:  cfg.AllowDevSigning,
		readinessMaxLag:  readinessLag,
		productUnitPrice: maxUint64(1, cfg.ProductUnitPrice),
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
	s.mux.HandleFunc("/p2p/status", s.handleP2PStatus)
	s.mux.HandleFunc("/p2p/message", s.handleP2PMessage)
	s.mux.HandleFunc("/p2p/peers", s.handleP2PPeers)
	s.mux.HandleFunc("/p2p/evidence", s.handleP2PEvidence)
	s.mux.HandleFunc("/sync/snapshot", s.handleSyncSnapshot)
	s.mux.HandleFunc("/status", s.handleStatus)
	s.mux.HandleFunc("/epoch", s.handleEpoch)
	s.mux.HandleFunc("/validators", s.handleValidators)
	s.mux.HandleFunc("/delegations", s.handleDelegations)
	s.mux.HandleFunc("/product/status", s.handleProductStatus)
	s.mux.HandleFunc("/product/proofs", s.handleProductProofs)
	s.mux.HandleFunc("/product/attestations", s.handleProductAttestations)
	s.mux.HandleFunc("/product/challenges", s.handleProductChallenges)
	s.mux.HandleFunc("/product/challenges/resolve", s.handleProductChallengeResolve)
	s.mux.HandleFunc("/product/settlements", s.handleProductSettlements)
	s.mux.HandleFunc("/product/billing/quote", s.handleProductBillingQuote)
	s.mux.HandleFunc("/validators/work-weight", s.handleSetWorkWeight)
	s.mux.HandleFunc("/validators/active", s.handleSetActive)
	s.mux.HandleFunc("/validators/bond", s.handleBondStake)
	s.mux.HandleFunc("/validators/unbond", s.handleUnbondStake)
	s.mux.HandleFunc("/validators/slash", s.handleSlashStake)
	s.mux.HandleFunc("/validators/jail", s.handleSetJailed)
	s.mux.HandleFunc("/accounts/", s.handleAccount)
	s.mux.HandleFunc("/nonce/", s.handleNonce)
	s.mux.HandleFunc("/blocks", s.handleBlocks)
	s.mux.HandleFunc("/tx", s.handleSubmitTx)
	s.mux.HandleFunc("/tx/sign", s.handleSignTx)
	s.mux.HandleFunc("/tx/sign-and-submit", s.handleSignAndSubmit)
	s.mux.HandleFunc("/wallets", s.handleWalletNew)
}

func (s *Server) handleP2PStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if s.p2p == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, s.p2p.Stats())
}

func (s *Server) handleP2PMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if s.p2p == nil || !s.p2p.Enabled() {
		writeError(w, http.StatusServiceUnavailable, errors.New("p2p is disabled"))
		return
	}
	remotePeer := remotePeerKey(r.RemoteAddr)
	if !s.p2p.AllowInboundPeer(remotePeer) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("p2p rate limit exceeded for peer %s", remotePeer))
		return
	}

	var env p2p.Envelope
	if err := decodeJSON(r, &env); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.p2p.HandleEnvelope(env); err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, p2p.ErrUnknownSender):
			status = http.StatusUnauthorized
		case errors.Is(err, p2p.ErrInvalidMessage):
			status = http.StatusUnauthorized
		case errors.Is(err, p2p.ErrDuplicateMessage):
			status = http.StatusConflict
		case errors.Is(err, p2p.ErrOutdatedMessage):
			status = http.StatusConflict
		case errors.Is(err, p2p.ErrConflictingMessage):
			status = http.StatusConflict
		case errors.Is(err, p2p.ErrUnsupportedType):
			status = http.StatusBadRequest
		}
		writeError(w, status, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Server) handleP2PPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.p2p == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"enabled": false,
				"peers":   []string{},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": s.p2p.Enabled(),
			"peers":   s.p2p.Peers(),
		})
		return
	case http.MethodPost:
		if !s.requireAdmin(w, r) {
			return
		}
		if s.p2p == nil || !s.p2p.Enabled() {
			writeError(w, http.StatusServiceUnavailable, errors.New("p2p is disabled"))
			return
		}

		var req struct {
			URL string `json:"url"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		added, err := s.p2p.AddPeer(req.URL)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		status := http.StatusOK
		if added {
			status = http.StatusCreated
		}
		writeJSON(w, status, map[string]any{
			"ok":    true,
			"added": added,
			"peers": s.p2p.Peers(),
		})
		return
	case http.MethodDelete:
		if !s.requireAdmin(w, r) {
			return
		}
		if s.p2p == nil || !s.p2p.Enabled() {
			writeError(w, http.StatusServiceUnavailable, errors.New("p2p is disabled"))
			return
		}

		target := strings.TrimSpace(r.URL.Query().Get("url"))
		if target == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing url query parameter"))
			return
		}
		removed, err := s.p2p.RemovePeer(target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"removed": removed,
			"peers":   s.p2p.Peers(),
		})
		return
	default:
		methodNotAllowed(w)
		return
	}
}

func (s *Server) handleP2PEvidence(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.p2p == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"enabled":  false,
				"evidence": []p2p.EquivocationEvidence{},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":  s.p2p.Enabled(),
			"evidence": s.p2p.Evidence(),
		})
		return
	case http.MethodPost:
		if !s.requireAdmin(w, r) {
			return
		}
		if s.p2p == nil || !s.p2p.Enabled() {
			writeError(w, http.StatusServiceUnavailable, errors.New("p2p is disabled"))
			return
		}
		var req struct {
			EvidenceID  string `json:"evidenceId"`
			BasisPoints uint64 `json:"basisPoints"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ev, err := s.p2p.ApplyEvidencePenalty(req.EvidenceID, req.BasisPoints)
		if err != nil {
			status := http.StatusBadRequest
			switch {
			case errors.Is(err, p2p.ErrEvidenceNotFound):
				status = http.StatusNotFound
			case errors.Is(err, p2p.ErrEvidenceApplied):
				status = http.StatusConflict
			}
			writeError(w, status, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"evidence": ev,
		})
		return
	default:
		methodNotAllowed(w)
		return
	}
}

func remotePeerKey(remoteAddr string) string {
	addr := strings.TrimSpace(remoteAddr)
	if addr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.ToLower(addr)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return strings.ToLower(addr)
	}
	return strings.ToLower(host)
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
	_, _ = fmt.Fprintf(w, "# HELP fastpos_chain_epoch Current epoch\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_chain_epoch gauge\n")
	_, _ = fmt.Fprintf(w, "fastpos_chain_epoch %d\n", m.Epoch)
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
	_, _ = fmt.Fprintf(w, "# HELP fastpos_expired_txs_total Expired transactions removed from mempool by age policy\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_expired_txs_total counter\n")
	_, _ = fmt.Fprintf(w, "fastpos_expired_txs_total %d\n", m.ExpiredTxTotal)
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
	_, _ = fmt.Fprintf(w, "# HELP fastpos_product_treasury_balance Product settlement treasury balance\n")
	_, _ = fmt.Fprintf(w, "# TYPE fastpos_product_treasury_balance gauge\n")
	_, _ = fmt.Fprintf(w, "fastpos_product_treasury_balance %d\n", m.ProductTreasuryBalance)
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

func (s *Server) handleEpoch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.chain.GetEpochInfo())
}

func (s *Server) handleSyncSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.chain.Snapshot())
}

func (s *Server) handleValidators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.chain.GetValidators())
}

func (s *Server) handleDelegations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	delegatorFilter := strings.TrimSpace(r.URL.Query().Get("delegator"))
	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	delegations := s.chain.GetDelegations()
	if delegatorFilter == "" && validatorFilter == "" {
		writeJSON(w, http.StatusOK, delegations)
		return
	}

	filtered := make([]chain.Delegation, 0, len(delegations))
	for _, delegation := range delegations {
		if delegatorFilter != "" && string(delegation.Delegator) != delegatorFilter {
			continue
		}
		if validatorFilter != "" && delegation.ValidatorID != validatorFilter {
			continue
		}
		filtered = append(filtered, delegation)
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleProductStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.chain.GetProductStatus())
}

func (s *Server) handleProductProofs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	includeInvalid := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("includeInvalid")), "true")
	proofs := s.chain.GetProductProofs()
	if validatorFilter == "" && includeInvalid {
		writeJSON(w, http.StatusOK, proofs)
		return
	}
	filtered := make([]chain.ProductProof, 0, len(proofs))
	for _, proof := range proofs {
		if validatorFilter != "" && proof.ValidatorID != validatorFilter {
			continue
		}
		if !includeInvalid && proof.Invalidated {
			continue
		}
		filtered = append(filtered, proof)
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleProductAttestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var tx chain.Transaction
	if err := decodeJSON(r, &tx); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if tx.Kind != chain.TxKindProductAttest {
		writeError(w, http.StatusBadRequest, fmt.Errorf("expected tx kind %q", chain.TxKindProductAttest))
		return
	}
	txID, err := s.chain.SubmitTx(tx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":   true,
		"txId": txID,
	})
}

func (s *Server) handleProductChallenges(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.chain.GetProductChallenges())
		return
	case http.MethodPost:
		var tx chain.Transaction
		if err := decodeJSON(r, &tx); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if tx.Kind != chain.TxKindProductChallenge {
			writeError(w, http.StatusBadRequest, fmt.Errorf("expected tx kind %q", chain.TxKindProductChallenge))
			return
		}
		txID, err := s.chain.SubmitTx(tx)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok":   true,
			"txId": txID,
		})
		return
	default:
		methodNotAllowed(w)
		return
	}
}

func (s *Server) handleProductChallengeResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var tx chain.Transaction
	if err := decodeJSON(r, &tx); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if tx.Kind != chain.TxKindProductResolveChallenge {
		writeError(w, http.StatusBadRequest, fmt.Errorf("expected tx kind %q", chain.TxKindProductResolveChallenge))
		return
	}
	txID, err := s.chain.SubmitTx(tx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":   true,
		"txId": txID,
	})
}

func (s *Server) handleProductSettlements(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settlements := s.chain.GetProductSettlements()
		validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
		if validatorFilter == "" {
			writeJSON(w, http.StatusOK, settlements)
			return
		}
		filtered := make([]chain.ProductSettlement, 0, len(settlements))
		for _, settlement := range settlements {
			if settlement.ValidatorID == validatorFilter {
				filtered = append(filtered, settlement)
			}
		}
		writeJSON(w, http.StatusOK, filtered)
		return
	case http.MethodPost:
		var tx chain.Transaction
		if err := decodeJSON(r, &tx); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if tx.Kind != chain.TxKindProductSettle {
			writeError(w, http.StatusBadRequest, fmt.Errorf("expected tx kind %q", chain.TxKindProductSettle))
			return
		}
		txID, err := s.chain.SubmitTx(tx)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok":   true,
			"txId": txID,
		})
		return
	default:
		methodNotAllowed(w)
		return
	}
}

func (s *Server) handleProductBillingQuote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	units := queryUint64(r, "units", 0)
	if units == 0 {
		writeError(w, http.StatusBadRequest, errors.New("units query parameter must be > 0"))
		return
	}
	amount := units * s.productUnitPrice
	if s.productUnitPrice > 0 && amount/s.productUnitPrice != units {
		writeError(w, http.StatusBadRequest, errors.New("quote amount overflow"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"units":        units,
		"unitPrice":    s.productUnitPrice,
		"amount":       amount,
		"suggestedFee": s.chain.MinTxFee(),
		"txKind":       chain.TxKindProductSettle,
	})
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
	s.writeValidatorState(w, req.ID)
}

func (s *Server) handleBondStake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		ID     string `json:"id"`
		Amount uint64 `json:"amount"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing id"))
		return
	}
	if err := s.chain.BondValidatorStake(req.ID, req.Amount); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.writeValidatorState(w, req.ID)
}

func (s *Server) handleUnbondStake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		ID     string `json:"id"`
		Amount uint64 `json:"amount"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing id"))
		return
	}
	if err := s.chain.UnbondValidatorStake(req.ID, req.Amount); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.writeValidatorState(w, req.ID)
}

func (s *Server) handleSlashStake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		ID          string `json:"id"`
		BasisPoints uint64 `json:"basisPoints"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing id"))
		return
	}
	slashed, err := s.chain.SlashValidatorStake(req.ID, req.BasisPoints)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	validator, ok := s.chain.GetValidator(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("validator %s not found", req.ID))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"slashed":   slashed,
		"validator": validator,
	})
}

func (s *Server) handleSetJailed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		ID     string `json:"id"`
		Jailed bool   `json:"jailed"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing id"))
		return
	}
	if err := s.chain.SetValidatorJailed(req.ID, req.Jailed); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.writeValidatorState(w, req.ID)
}

func (s *Server) writeValidatorState(w http.ResponseWriter, id string) {
	validator, ok := s.chain.GetValidator(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("validator %s not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"validator": validator,
	})
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
		PrivateKey  string        `json:"privateKey"`
		Kind        string        `json:"kind"`
		To          chain.Address `json:"to"`
		Amount      uint64        `json:"amount"`
		Fee         uint64        `json:"fee"`
		Nonce       uint64        `json:"nonce"`
		Timestamp   int64         `json:"timestamp"`
		ValidatorID string        `json:"validatorId"`
		BasisPoints uint64        `json:"basisPoints"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.PrivateKey == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing privateKey"))
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
		Kind:        req.Kind,
		From:        addr,
		To:          req.To,
		Amount:      req.Amount,
		Fee:         req.Fee,
		Nonce:       req.Nonce,
		Timestamp:   req.Timestamp,
		ValidatorID: req.ValidatorID,
		BasisPoints: req.BasisPoints,
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
		PrivateKey  string        `json:"privateKey"`
		Kind        string        `json:"kind"`
		To          chain.Address `json:"to"`
		Amount      uint64        `json:"amount"`
		Fee         uint64        `json:"fee"`
		Nonce       uint64        `json:"nonce"`
		Timestamp   int64         `json:"timestamp"`
		ValidatorID string        `json:"validatorId"`
		BasisPoints uint64        `json:"basisPoints"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.PrivateKey == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing privateKey"))
		return
	}

	_, from, err := chain.PublicAndAddressFromPrivateKeyHex(req.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Nonce == 0 {
		nonce, err := s.chain.NextNonce(from)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req.Nonce = nonce
	}

	tx := chain.Transaction{
		Kind:        req.Kind,
		From:        from,
		To:          req.To,
		Amount:      req.Amount,
		Fee:         req.Fee,
		Nonce:       req.Nonce,
		Timestamp:   req.Timestamp,
		ValidatorID: req.ValidatorID,
		BasisPoints: req.BasisPoints,
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

func queryUint64(r *http.Request, key string, defaultValue uint64) uint64 {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
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
