package node

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"fastpos/internal/chain"
	"fastpos/internal/p2p"
)

const maxListQueryLimit = 1_000

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
	s.mux.HandleFunc("/product/attestations/stats", s.handleProductAttestationStats)
	s.mux.HandleFunc("/product/attestations/pending", s.handleProductPendingAttestations)
	s.mux.HandleFunc("/product/challenges", s.handleProductChallenges)
	s.mux.HandleFunc("/product/challenges/stats", s.handleProductChallengeStats)
	s.mux.HandleFunc("/product/challenges/resolve", s.handleProductChallengeResolve)
	s.mux.HandleFunc("/product/settlements/lookup", s.handleProductSettlementLookup)
	s.mux.HandleFunc("/product/settlements/stats", s.handleProductSettlementStats)
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
	s.mux.HandleFunc("/tx/pending", s.handlePendingTx)
	s.mux.HandleFunc("/tx/finalized", s.handleFinalizedTx)
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

	idFilter := strings.TrimSpace(r.URL.Query().Get("id"))
	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	proofRefFilter := strings.TrimSpace(r.URL.Query().Get("proofRef"))
	reporterFilter := strings.TrimSpace(r.URL.Query().Get("reporter"))
	includeInvalid, err := queryBool(r, "includeInvalid", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	withMeta, err := queryBool(r, "withMeta", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, limit, err := queryOffsetLimit(r, maxListQueryLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	epochFilter, hasEpochFilter, err := optionalQueryUint64(r, "epoch")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minScoreFilter, hasMinScoreFilter, err := optionalQueryUint64(r, "minScore")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	maxScoreFilter, hasMaxScoreFilter, err := optionalQueryUint64(r, "maxScore")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	proofs := s.chain.GetProductProofs()
	filtered := make([]chain.ProductProof, 0, len(proofs))
	for _, proof := range proofs {
		if idFilter != "" && proof.ID != idFilter {
			continue
		}
		if validatorFilter != "" && proof.ValidatorID != validatorFilter {
			continue
		}
		if proofRefFilter != "" && proof.ProofRef != proofRefFilter {
			continue
		}
		if reporterFilter != "" && string(proof.Reporter) != reporterFilter {
			continue
		}
		if hasEpochFilter && proof.Epoch != epochFilter {
			continue
		}
		if hasMinScoreFilter && proof.Score < minScoreFilter {
			continue
		}
		if hasMaxScoreFilter && proof.Score > maxScoreFilter {
			continue
		}
		if !includeInvalid && proof.Invalidated {
			continue
		}
		filtered = append(filtered, proof)
	}
	start, end := paginationBounds(len(filtered), offset, limit)
	page := filtered[start:end]
	if withMeta {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":   page,
			"total":   len(filtered),
			"offset":  start,
			"limit":   limit,
			"count":   len(page),
			"hasMore": end < len(filtered),
		})
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleProductAttestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	idempotent, err := queryBool(r, "idempotent", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
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
		if errors.Is(err, chain.ErrProductAttestationDuplicateVote) || errors.Is(err, chain.ErrProductProofAlreadyFinalized) {
			if idempotent {
				if item, ok := findPendingTx(s.chain.GetPendingTransactions(), func(pending chain.PendingTransaction) bool {
					ptx := pending.Transaction
					return txKindOrTransfer(ptx) == chain.TxKindProductAttest &&
						ptx.From == tx.From &&
						ptx.To == tx.To &&
						ptx.ValidatorID == tx.ValidatorID &&
						ptx.Amount == tx.Amount &&
						ptx.BasisPoints == tx.BasisPoints
				}); ok {
					writeJSON(w, http.StatusOK, map[string]any{
						"ok":         true,
						"idempotent": true,
						"duplicate":  true,
						"state":      chain.TxStatePending,
						"txId":       item.TxID,
					})
					return
				}
				if proof, ok := findProductProofForAttestation(s.chain.GetProductProofs(), tx); ok {
					writeJSON(w, http.StatusOK, map[string]any{
						"ok":         true,
						"idempotent": true,
						"duplicate":  true,
						"state":      chain.TxStateFinalized,
						"proof":      proof,
					})
					return
				}
				if pending, ok := findPendingAttestationForTx(s.chain.GetProductPendingAttestations(), tx); ok {
					writeJSON(w, http.StatusOK, map[string]any{
						"ok":                 true,
						"idempotent":         true,
						"duplicate":          true,
						"state":              chain.TxStatePending,
						"pendingAttestation": pending,
					})
					return
				}
			}
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":   true,
		"txId": txID,
	})
}

func (s *Server) handleProductPendingAttestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	pending := s.chain.GetProductPendingAttestations()
	idFilter := strings.TrimSpace(r.URL.Query().Get("id"))
	proofIDFilter := strings.TrimSpace(r.URL.Query().Get("proofId"))
	proofRefFilter := strings.TrimSpace(r.URL.Query().Get("proofRef"))
	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	withMeta, err := queryBool(r, "withMeta", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, limit, err := queryOffsetLimit(r, maxListQueryLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	epochFilter, hasEpochFilter, err := optionalQueryUint64(r, "epoch")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minCollectedStakeFilter, hasMinCollectedStakeFilter, err := optionalQueryUint64(r, "minCollectedStake")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sinceMsFilter, hasSinceMsFilter, err := optionalQueryInt64(r, "sinceMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	untilMsFilter, hasUntilMsFilter, err := optionalQueryInt64(r, "untilMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	filtered := make([]chain.ProductPendingAttestation, 0, len(pending))
	for _, att := range pending {
		if idFilter != "" && att.ID != idFilter {
			continue
		}
		if proofIDFilter != "" && att.ID != proofIDFilter {
			continue
		}
		if proofRefFilter != "" && att.ProofRef != proofRefFilter {
			continue
		}
		if validatorFilter != "" && att.ValidatorID != validatorFilter {
			continue
		}
		if hasEpochFilter && att.Epoch != epochFilter {
			continue
		}
		if hasMinCollectedStakeFilter && att.CollectedStake < minCollectedStakeFilter {
			continue
		}
		if hasSinceMsFilter && att.LastUpdatedMs < sinceMsFilter {
			continue
		}
		if hasUntilMsFilter && att.LastUpdatedMs > untilMsFilter {
			continue
		}
		filtered = append(filtered, att)
	}
	start, end := paginationBounds(len(filtered), offset, limit)
	page := filtered[start:end]
	if withMeta {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":   page,
			"total":   len(filtered),
			"offset":  start,
			"limit":   limit,
			"count":   len(page),
			"hasMore": end < len(filtered),
		})
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleProductAttestationStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	pending := s.chain.GetProductPendingAttestations()
	idFilter := strings.TrimSpace(r.URL.Query().Get("id"))
	proofIDFilter := strings.TrimSpace(r.URL.Query().Get("proofId"))
	proofRefFilter := strings.TrimSpace(r.URL.Query().Get("proofRef"))
	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	epochFilter, hasEpochFilter, err := optionalQueryUint64(r, "epoch")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minCollectedStakeFilter, hasMinCollectedStakeFilter, err := optionalQueryUint64(r, "minCollectedStake")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sinceMsFilter, hasSinceMsFilter, err := optionalQueryInt64(r, "sinceMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	untilMsFilter, hasUntilMsFilter, err := optionalQueryInt64(r, "untilMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	type attestationStatsByValidator struct {
		ValidatorID    string `json:"validatorId"`
		Count          int    `json:"count"`
		RequiredStake  uint64 `json:"requiredStake"`
		CollectedStake uint64 `json:"collectedStake"`
	}

	count := 0
	totalRequired := uint64(0)
	totalCollected := uint64(0)
	progressBpsSum := uint64(0)
	byValidatorMap := make(map[string]attestationStatsByValidator)
	for _, att := range pending {
		if idFilter != "" && att.ID != idFilter {
			continue
		}
		if proofIDFilter != "" && att.ID != proofIDFilter {
			continue
		}
		if proofRefFilter != "" && att.ProofRef != proofRefFilter {
			continue
		}
		if validatorFilter != "" && att.ValidatorID != validatorFilter {
			continue
		}
		if hasEpochFilter && att.Epoch != epochFilter {
			continue
		}
		if hasMinCollectedStakeFilter && att.CollectedStake < minCollectedStakeFilter {
			continue
		}
		if hasSinceMsFilter && att.LastUpdatedMs < sinceMsFilter {
			continue
		}
		if hasUntilMsFilter && att.LastUpdatedMs > untilMsFilter {
			continue
		}

		nextRequired := totalRequired + att.RequiredStake
		if nextRequired < totalRequired {
			writeError(w, http.StatusInternalServerError, errors.New("required stake overflow"))
			return
		}
		totalRequired = nextRequired

		nextCollected := totalCollected + att.CollectedStake
		if nextCollected < totalCollected {
			writeError(w, http.StatusInternalServerError, errors.New("collected stake overflow"))
			return
		}
		totalCollected = nextCollected

		progressBps := uint64(0)
		if att.RequiredStake > 0 {
			collected := att.CollectedStake
			if collected > att.RequiredStake {
				collected = att.RequiredStake
			}
			progressBps = (collected * 10_000) / att.RequiredStake
		}
		nextProgress := progressBpsSum + progressBps
		if nextProgress < progressBpsSum {
			writeError(w, http.StatusInternalServerError, errors.New("attestation progress overflow"))
			return
		}
		progressBpsSum = nextProgress

		entry := byValidatorMap[att.ValidatorID]
		entry.ValidatorID = att.ValidatorID
		entry.Count++
		nextValidatorRequired := entry.RequiredStake + att.RequiredStake
		if nextValidatorRequired < entry.RequiredStake {
			writeError(w, http.StatusInternalServerError, errors.New("validator required stake overflow"))
			return
		}
		entry.RequiredStake = nextValidatorRequired
		nextValidatorCollected := entry.CollectedStake + att.CollectedStake
		if nextValidatorCollected < entry.CollectedStake {
			writeError(w, http.StatusInternalServerError, errors.New("validator collected stake overflow"))
			return
		}
		entry.CollectedStake = nextValidatorCollected
		byValidatorMap[att.ValidatorID] = entry

		count++
	}

	avgProgressBps := uint64(0)
	if count > 0 {
		avgProgressBps = progressBpsSum / uint64(count)
	}

	byValidator := make([]attestationStatsByValidator, 0, len(byValidatorMap))
	for _, entry := range byValidatorMap {
		byValidator = append(byValidator, entry)
	}
	sort.SliceStable(byValidator, func(i, j int) bool {
		return byValidator[i].ValidatorID < byValidator[j].ValidatorID
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"count":               count,
		"totalRequiredStake":  totalRequired,
		"totalCollectedStake": totalCollected,
		"averageProgressBps":  avgProgressBps,
		"byValidator":         byValidator,
	})
}

func (s *Server) handleProductChallenges(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		idFilter := strings.TrimSpace(r.URL.Query().Get("id"))
		proofFilter := strings.TrimSpace(r.URL.Query().Get("proofId"))
		challengerFilter := strings.TrimSpace(r.URL.Query().Get("challenger"))
		resolverFilter := strings.TrimSpace(r.URL.Query().Get("resolver"))
		openOnly, err := queryBool(r, "openOnly", false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		withMeta, err := queryBool(r, "withMeta", false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		offset, limit, err := queryOffsetLimit(r, maxListQueryLimit)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		successfulFilter, hasSuccessfulFilter, err := optionalQueryBool(r, "successful")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		minBondFilter, hasMinBondFilter, err := optionalQueryUint64(r, "minBond")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		sinceMsFilter, hasSinceMsFilter, err := optionalQueryInt64(r, "sinceMs")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		untilMsFilter, hasUntilMsFilter, err := optionalQueryInt64(r, "untilMs")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		challenges := s.chain.GetProductChallenges()
		filtered := make([]chain.ProductChallenge, 0, len(challenges))
		for _, challenge := range challenges {
			if idFilter != "" && challenge.ID != idFilter {
				continue
			}
			if proofFilter != "" && challenge.ProofID != proofFilter {
				continue
			}
			if challengerFilter != "" && string(challenge.Challenger) != challengerFilter {
				continue
			}
			if resolverFilter != "" && string(challenge.Resolver) != resolverFilter {
				continue
			}
			if openOnly && !challenge.Open {
				continue
			}
			if hasSuccessfulFilter && challenge.Successful != successfulFilter {
				continue
			}
			if hasMinBondFilter && challenge.Bond < minBondFilter {
				continue
			}
			if hasSinceMsFilter && challenge.CreatedMs < sinceMsFilter {
				continue
			}
			if hasUntilMsFilter && challenge.CreatedMs > untilMsFilter {
				continue
			}
			filtered = append(filtered, challenge)
		}
		start, end := paginationBounds(len(filtered), offset, limit)
		page := filtered[start:end]
		if withMeta {
			writeJSON(w, http.StatusOK, map[string]any{
				"items":   page,
				"total":   len(filtered),
				"offset":  start,
				"limit":   limit,
				"count":   len(page),
				"hasMore": end < len(filtered),
			})
			return
		}
		writeJSON(w, http.StatusOK, page)
		return
	case http.MethodPost:
		idempotent, err := queryBool(r, "idempotent", false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
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
			if errors.Is(err, chain.ErrProductChallengeOpen) || errors.Is(err, chain.ErrProductChallengeClosed) {
				if idempotent {
					if item, ok := findPendingTx(s.chain.GetPendingTransactions(), func(pending chain.PendingTransaction) bool {
						ptx := pending.Transaction
						return txKindOrTransfer(ptx) == chain.TxKindProductChallenge &&
							ptx.From == tx.From &&
							ptx.To == tx.To &&
							ptx.Amount == tx.Amount
					}); ok {
						writeJSON(w, http.StatusOK, map[string]any{
							"ok":         true,
							"idempotent": true,
							"duplicate":  true,
							"state":      chain.TxStatePending,
							"txId":       item.TxID,
						})
						return
					}
					if challenge, ok := findProductChallengeForProof(s.chain.GetProductChallenges(), string(tx.To)); ok {
						state := chain.TxStatePending
						if !challenge.Open {
							state = chain.TxStateFinalized
						}
						writeJSON(w, http.StatusOK, map[string]any{
							"ok":         true,
							"idempotent": true,
							"duplicate":  true,
							"state":      state,
							"challenge":  challenge,
						})
						return
					}
				}
				writeError(w, http.StatusConflict, err)
				return
			}
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
	idempotent, err := queryBool(r, "idempotent", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
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
		if errors.Is(err, chain.ErrProductChallengeDuplicateVote) || errors.Is(err, chain.ErrProductChallengeClosed) {
			if idempotent {
				if item, ok := findPendingTx(s.chain.GetPendingTransactions(), func(pending chain.PendingTransaction) bool {
					ptx := pending.Transaction
					return txKindOrTransfer(ptx) == chain.TxKindProductResolveChallenge &&
						ptx.From == tx.From &&
						ptx.To == tx.To &&
						ptx.Amount == tx.Amount &&
						ptx.BasisPoints == tx.BasisPoints
				}); ok {
					writeJSON(w, http.StatusOK, map[string]any{
						"ok":         true,
						"idempotent": true,
						"duplicate":  true,
						"state":      chain.TxStatePending,
						"txId":       item.TxID,
					})
					return
				}
				if challenge, ok := findProductChallengeByID(s.chain.GetProductChallenges(), string(tx.To)); ok {
					state := chain.TxStatePending
					if !challenge.Open {
						state = chain.TxStateFinalized
					}
					writeJSON(w, http.StatusOK, map[string]any{
						"ok":         true,
						"idempotent": true,
						"duplicate":  true,
						"state":      state,
						"challenge":  challenge,
					})
					return
				}
			}
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":   true,
		"txId": txID,
	})
}

func (s *Server) handleProductChallengeStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	idFilter := strings.TrimSpace(r.URL.Query().Get("id"))
	proofFilter := strings.TrimSpace(r.URL.Query().Get("proofId"))
	challengerFilter := strings.TrimSpace(r.URL.Query().Get("challenger"))
	resolverFilter := strings.TrimSpace(r.URL.Query().Get("resolver"))
	openOnly, err := queryBool(r, "openOnly", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	successfulFilter, hasSuccessfulFilter, err := optionalQueryBool(r, "successful")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minBondFilter, hasMinBondFilter, err := optionalQueryUint64(r, "minBond")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sinceMsFilter, hasSinceMsFilter, err := optionalQueryInt64(r, "sinceMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	untilMsFilter, hasUntilMsFilter, err := optionalQueryInt64(r, "untilMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	type challengeStatsByChallenger struct {
		Challenger string `json:"challenger"`
		Count      int    `json:"count"`
		OpenCount  int    `json:"openCount"`
		Successful int    `json:"successful"`
		Rejected   int    `json:"rejected"`
		Bond       uint64 `json:"bond"`
	}
	type challengeStatsByResolver struct {
		Resolver   string `json:"resolver"`
		Count      int    `json:"count"`
		Successful int    `json:"successful"`
		Rejected   int    `json:"rejected"`
		Bond       uint64 `json:"bond"`
	}

	count := 0
	openCount := 0
	successfulCount := 0
	rejectedCount := 0
	totalBond := uint64(0)
	openBond := uint64(0)
	resolvedBond := uint64(0)
	byChallengerMap := make(map[string]challengeStatsByChallenger)
	byResolverMap := make(map[string]challengeStatsByResolver)
	challenges := s.chain.GetProductChallenges()
	for _, challenge := range challenges {
		if idFilter != "" && challenge.ID != idFilter {
			continue
		}
		if proofFilter != "" && challenge.ProofID != proofFilter {
			continue
		}
		if challengerFilter != "" && string(challenge.Challenger) != challengerFilter {
			continue
		}
		if resolverFilter != "" && string(challenge.Resolver) != resolverFilter {
			continue
		}
		if openOnly && !challenge.Open {
			continue
		}
		if hasSuccessfulFilter && challenge.Successful != successfulFilter {
			continue
		}
		if hasMinBondFilter && challenge.Bond < minBondFilter {
			continue
		}
		if hasSinceMsFilter && challenge.CreatedMs < sinceMsFilter {
			continue
		}
		if hasUntilMsFilter && challenge.CreatedMs > untilMsFilter {
			continue
		}

		nextTotalBond := totalBond + challenge.Bond
		if nextTotalBond < totalBond {
			writeError(w, http.StatusInternalServerError, errors.New("challenge bond overflow"))
			return
		}
		totalBond = nextTotalBond
		count++
		if challenge.Open {
			nextOpenBond := openBond + challenge.Bond
			if nextOpenBond < openBond {
				writeError(w, http.StatusInternalServerError, errors.New("open challenge bond overflow"))
				return
			}
			openCount++
			openBond = nextOpenBond
		} else {
			nextResolvedBond := resolvedBond + challenge.Bond
			if nextResolvedBond < resolvedBond {
				writeError(w, http.StatusInternalServerError, errors.New("resolved challenge bond overflow"))
				return
			}
			resolvedBond = nextResolvedBond
			if challenge.Successful {
				successfulCount++
			} else {
				rejectedCount++
			}
		}

		challengerEntry := byChallengerMap[string(challenge.Challenger)]
		challengerEntry.Challenger = string(challenge.Challenger)
		challengerEntry.Count++
		nextChallengerBond := challengerEntry.Bond + challenge.Bond
		if nextChallengerBond < challengerEntry.Bond {
			writeError(w, http.StatusInternalServerError, errors.New("challenger bond overflow"))
			return
		}
		challengerEntry.Bond = nextChallengerBond
		if challenge.Open {
			challengerEntry.OpenCount++
		} else if challenge.Successful {
			challengerEntry.Successful++
		} else {
			challengerEntry.Rejected++
		}
		byChallengerMap[string(challenge.Challenger)] = challengerEntry

		if challenge.Resolver != "" {
			resolverEntry := byResolverMap[string(challenge.Resolver)]
			resolverEntry.Resolver = string(challenge.Resolver)
			resolverEntry.Count++
			nextResolverBond := resolverEntry.Bond + challenge.Bond
			if nextResolverBond < resolverEntry.Bond {
				writeError(w, http.StatusInternalServerError, errors.New("resolver bond overflow"))
				return
			}
			resolverEntry.Bond = nextResolverBond
			if challenge.Successful {
				resolverEntry.Successful++
			} else {
				resolverEntry.Rejected++
			}
			byResolverMap[string(challenge.Resolver)] = resolverEntry
		}
	}

	byChallenger := make([]challengeStatsByChallenger, 0, len(byChallengerMap))
	for _, entry := range byChallengerMap {
		byChallenger = append(byChallenger, entry)
	}
	sort.SliceStable(byChallenger, func(i, j int) bool {
		return byChallenger[i].Challenger < byChallenger[j].Challenger
	})

	byResolver := make([]challengeStatsByResolver, 0, len(byResolverMap))
	for _, entry := range byResolverMap {
		byResolver = append(byResolver, entry)
	}
	sort.SliceStable(byResolver, func(i, j int) bool {
		return byResolver[i].Resolver < byResolver[j].Resolver
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"count":        count,
		"openCount":    openCount,
		"closedCount":  count - openCount,
		"successful":   successfulCount,
		"rejected":     rejectedCount,
		"totalBond":    totalBond,
		"openBond":     openBond,
		"resolvedBond": resolvedBond,
		"byChallenger": byChallenger,
		"byResolver":   byResolver,
	})
}

func (s *Server) handleProductSettlements(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settlements := s.chain.GetProductSettlements()
		idFilter := strings.TrimSpace(r.URL.Query().Get("id"))
		referenceFilter := strings.TrimSpace(r.URL.Query().Get("reference"))
		payerFilter := strings.TrimSpace(r.URL.Query().Get("payer"))
		validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
		withMeta, err := queryBool(r, "withMeta", false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		offset, limit, err := queryOffsetLimit(r, maxListQueryLimit)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		epochFilter, hasEpochFilter, err := optionalQueryUint64(r, "epoch")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		minAmountFilter, hasMinAmountFilter, err := optionalQueryUint64(r, "minAmount")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		maxAmountFilter, hasMaxAmountFilter, err := optionalQueryUint64(r, "maxAmount")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		sinceMsFilter, hasSinceMsFilter, err := optionalQueryInt64(r, "sinceMs")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		untilMsFilter, hasUntilMsFilter, err := optionalQueryInt64(r, "untilMs")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		filtered := make([]chain.ProductSettlement, 0, len(settlements))
		for _, settlement := range settlements {
			if idFilter != "" && settlement.ID != idFilter {
				continue
			}
			if referenceFilter != "" && settlement.Reference != referenceFilter {
				continue
			}
			if payerFilter != "" && string(settlement.Payer) != payerFilter {
				continue
			}
			if validatorFilter != "" && settlement.ValidatorID != validatorFilter {
				continue
			}
			if hasEpochFilter && settlement.Epoch != epochFilter {
				continue
			}
			if hasMinAmountFilter && settlement.Amount < minAmountFilter {
				continue
			}
			if hasMaxAmountFilter && settlement.Amount > maxAmountFilter {
				continue
			}
			if hasSinceMsFilter && settlement.Timestamp < sinceMsFilter {
				continue
			}
			if hasUntilMsFilter && settlement.Timestamp > untilMsFilter {
				continue
			}
			filtered = append(filtered, settlement)
		}
		start, end := paginationBounds(len(filtered), offset, limit)
		page := filtered[start:end]
		if withMeta {
			writeJSON(w, http.StatusOK, map[string]any{
				"items":   page,
				"total":   len(filtered),
				"offset":  start,
				"limit":   limit,
				"count":   len(page),
				"hasMore": end < len(filtered),
			})
			return
		}
		writeJSON(w, http.StatusOK, page)
		return
	case http.MethodPost:
		idempotent, err := queryBool(r, "idempotent", false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
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
			if errors.Is(err, chain.ErrProductSettlementDuplicate) {
				if idempotent {
					settlement, ok := s.chain.GetProductSettlementByPayerReference(tx.From, string(tx.To))
					if ok {
						writeJSON(w, http.StatusOK, map[string]any{
							"ok":         true,
							"idempotent": true,
							"duplicate":  true,
							"state":      chain.TxStateFinalized,
							"settlement": settlement,
						})
						return
					}
					pending := s.chain.GetPendingTransactions()
					for _, item := range pending {
						pendingTx := item.Transaction
						kind := txKindOrTransfer(pendingTx)
						if kind != chain.TxKindProductSettle {
							continue
						}
						if pendingTx.From != tx.From || pendingTx.To != tx.To {
							continue
						}
						writeJSON(w, http.StatusOK, map[string]any{
							"ok":         true,
							"idempotent": true,
							"duplicate":  true,
							"state":      chain.TxStatePending,
							"txId":       item.TxID,
						})
						return
					}
				}
				writeError(w, http.StatusConflict, err)
				return
			}
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

func (s *Server) handleProductSettlementLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	payer := strings.TrimSpace(r.URL.Query().Get("payer"))
	if payer == "" {
		writeError(w, http.StatusBadRequest, errors.New("payer query parameter is required"))
		return
	}
	reference := strings.TrimSpace(r.URL.Query().Get("reference"))
	if reference == "" {
		writeError(w, http.StatusBadRequest, errors.New("reference query parameter is required"))
		return
	}
	includePending, err := queryBool(r, "includePending", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	settlement, ok := s.chain.GetProductSettlementByPayerReference(chain.Address(payer), reference)
	if ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"state":      chain.TxStateFinalized,
			"settlement": settlement,
		})
		return
	}
	if includePending {
		pending, found := findPendingTx(s.chain.GetPendingTransactions(), func(item chain.PendingTransaction) bool {
			tx := item.Transaction
			return txKindOrTransfer(tx) == chain.TxKindProductSettle &&
				tx.From == chain.Address(payer) &&
				string(tx.To) == reference
		})
		if found {
			writeJSON(w, http.StatusOK, map[string]any{
				"state": chain.TxStatePending,
				"txId":  pending.TxID,
			})
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Errorf("settlement not found for payer=%s reference=%s", payer, reference))
}

func (s *Server) handleProductSettlementStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	settlements := s.chain.GetProductSettlements()
	idFilter := strings.TrimSpace(r.URL.Query().Get("id"))
	referenceFilter := strings.TrimSpace(r.URL.Query().Get("reference"))
	payerFilter := strings.TrimSpace(r.URL.Query().Get("payer"))
	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	epochFilter, hasEpochFilter, err := optionalQueryUint64(r, "epoch")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minAmountFilter, hasMinAmountFilter, err := optionalQueryUint64(r, "minAmount")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	maxAmountFilter, hasMaxAmountFilter, err := optionalQueryUint64(r, "maxAmount")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sinceMsFilter, hasSinceMsFilter, err := optionalQueryInt64(r, "sinceMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	untilMsFilter, hasUntilMsFilter, err := optionalQueryInt64(r, "untilMs")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	type settlementStatsByValidator struct {
		ValidatorID string `json:"validatorId"`
		Count       int    `json:"count"`
		Amount      uint64 `json:"amount"`
	}
	type settlementStatsByEpoch struct {
		Epoch  uint64 `json:"epoch"`
		Count  int    `json:"count"`
		Amount uint64 `json:"amount"`
	}

	totalCount := 0
	totalAmount := uint64(0)
	byValidatorMap := make(map[string]settlementStatsByValidator)
	byEpochMap := make(map[uint64]settlementStatsByEpoch)
	for _, settlement := range settlements {
		if idFilter != "" && settlement.ID != idFilter {
			continue
		}
		if referenceFilter != "" && settlement.Reference != referenceFilter {
			continue
		}
		if payerFilter != "" && string(settlement.Payer) != payerFilter {
			continue
		}
		if validatorFilter != "" && settlement.ValidatorID != validatorFilter {
			continue
		}
		if hasEpochFilter && settlement.Epoch != epochFilter {
			continue
		}
		if hasMinAmountFilter && settlement.Amount < minAmountFilter {
			continue
		}
		if hasMaxAmountFilter && settlement.Amount > maxAmountFilter {
			continue
		}
		if hasSinceMsFilter && settlement.Timestamp < sinceMsFilter {
			continue
		}
		if hasUntilMsFilter && settlement.Timestamp > untilMsFilter {
			continue
		}

		nextTotal := totalAmount + settlement.Amount
		if nextTotal < totalAmount {
			writeError(w, http.StatusInternalServerError, errors.New("settlement amount overflow"))
			return
		}
		totalAmount = nextTotal
		totalCount++

		valEntry := byValidatorMap[settlement.ValidatorID]
		valEntry.ValidatorID = settlement.ValidatorID
		valEntry.Count++
		valEntry.Amount += settlement.Amount
		byValidatorMap[settlement.ValidatorID] = valEntry

		epochEntry := byEpochMap[settlement.Epoch]
		epochEntry.Epoch = settlement.Epoch
		epochEntry.Count++
		epochEntry.Amount += settlement.Amount
		byEpochMap[settlement.Epoch] = epochEntry
	}

	byValidator := make([]settlementStatsByValidator, 0, len(byValidatorMap))
	for _, entry := range byValidatorMap {
		byValidator = append(byValidator, entry)
	}
	sort.SliceStable(byValidator, func(i, j int) bool {
		return byValidator[i].ValidatorID < byValidator[j].ValidatorID
	})

	byEpoch := make([]settlementStatsByEpoch, 0, len(byEpochMap))
	for _, entry := range byEpochMap {
		byEpoch = append(byEpoch, entry)
	}
	sort.SliceStable(byEpoch, func(i, j int) bool {
		return byEpoch[i].Epoch < byEpoch[j].Epoch
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"count":       totalCount,
		"totalAmount": totalAmount,
		"byValidator": byValidator,
		"byEpoch":     byEpoch,
	})
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

func (s *Server) handlePendingTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	fromFilter := strings.TrimSpace(r.URL.Query().Get("from"))
	toFilter := strings.TrimSpace(r.URL.Query().Get("to"))
	kindFilter := strings.TrimSpace(r.URL.Query().Get("kind"))
	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	withMeta, err := queryBool(r, "withMeta", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, limit, err := queryOffsetLimit(r, maxListQueryLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minFeeFilter, hasMinFeeFilter, err := optionalQueryUint64(r, "minFee")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	maxFeeFilter, hasMaxFeeFilter, err := optionalQueryUint64(r, "maxFee")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	pending := s.chain.GetPendingTransactions()
	filtered := make([]chain.PendingTransaction, 0, len(pending))
	for _, item := range pending {
		tx := item.Transaction
		kind := txKindOrTransfer(tx)
		if fromFilter != "" && string(tx.From) != fromFilter {
			continue
		}
		if toFilter != "" && string(tx.To) != toFilter {
			continue
		}
		if kindFilter != "" && kind != kindFilter {
			continue
		}
		if validatorFilter != "" && tx.ValidatorID != validatorFilter {
			continue
		}
		if hasMinFeeFilter && tx.Fee < minFeeFilter {
			continue
		}
		if hasMaxFeeFilter && tx.Fee > maxFeeFilter {
			continue
		}
		filtered = append(filtered, item)
	}
	start, end := paginationBounds(len(filtered), offset, limit)
	page := filtered[start:end]
	if withMeta {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":   page,
			"total":   len(filtered),
			"offset":  start,
			"limit":   limit,
			"count":   len(page),
			"hasMore": end < len(filtered),
		})
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleFinalizedTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	fromFilter := strings.TrimSpace(r.URL.Query().Get("from"))
	toFilter := strings.TrimSpace(r.URL.Query().Get("to"))
	kindFilter := strings.TrimSpace(r.URL.Query().Get("kind"))
	validatorFilter := strings.TrimSpace(r.URL.Query().Get("validatorId"))
	withMeta, err := queryBool(r, "withMeta", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, limit, err := queryOffsetLimit(r, maxListQueryLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minFeeFilter, hasMinFeeFilter, err := optionalQueryUint64(r, "minFee")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	maxFeeFilter, hasMaxFeeFilter, err := optionalQueryUint64(r, "maxFee")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	minHeightFilter, hasMinHeightFilter, err := optionalQueryUint64(r, "minHeight")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	maxHeightFilter, hasMaxHeightFilter, err := optionalQueryUint64(r, "maxHeight")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	finalized := s.chain.GetFinalizedTransactions()
	filtered := make([]chain.TransactionLookup, 0, len(finalized))
	for _, item := range finalized {
		tx := item.Transaction
		kind := txKindOrTransfer(tx)
		if fromFilter != "" && string(tx.From) != fromFilter {
			continue
		}
		if toFilter != "" && string(tx.To) != toFilter {
			continue
		}
		if kindFilter != "" && kind != kindFilter {
			continue
		}
		if validatorFilter != "" && tx.ValidatorID != validatorFilter {
			continue
		}
		if hasMinFeeFilter && tx.Fee < minFeeFilter {
			continue
		}
		if hasMaxFeeFilter && tx.Fee > maxFeeFilter {
			continue
		}
		if item.Finalized != nil {
			if hasMinHeightFilter && item.Finalized.Height < minHeightFilter {
				continue
			}
			if hasMaxHeightFilter && item.Finalized.Height > maxHeightFilter {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	start, end := paginationBounds(len(filtered), offset, limit)
	page := filtered[start:end]
	if withMeta {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":   page,
			"total":   len(filtered),
			"offset":  start,
			"limit":   limit,
			"count":   len(page),
			"hasMore": end < len(filtered),
		})
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleSubmitTx(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		txID := strings.TrimSpace(r.URL.Query().Get("id"))
		if txID == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing tx id"))
			return
		}
		record, ok := s.chain.GetTransaction(txID)
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("transaction %s not found", txID))
			return
		}
		writeJSON(w, http.StatusOK, record)
		return
	case http.MethodPost:
		idempotent, err := queryBool(r, "idempotent", false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		var tx chain.Transaction
		if err := decodeJSON(r, &tx); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		txID, err := s.chain.SubmitTx(tx)
		if err != nil {
			if errors.Is(err, chain.ErrDuplicateTransaction) || errors.Is(err, chain.ErrTransactionAlreadyFinalized) {
				if idempotent {
					record, ok := s.chain.GetTransaction(tx.ID())
					if ok {
						writeJSON(w, http.StatusOK, map[string]any{
							"ok":         true,
							"idempotent": true,
							"duplicate":  true,
							"txId":       record.TxID,
							"state":      record.State,
						})
						return
					}
					writeJSON(w, http.StatusOK, map[string]any{
						"ok":         true,
						"idempotent": true,
						"duplicate":  true,
						"txId":       tx.ID(),
					})
					return
				}
				writeError(w, http.StatusConflict, err)
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"txId": txID})
		return
	default:
		methodNotAllowed(w)
		return
	}
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

func queryBool(r *http.Request, key string, defaultValue bool) (bool, error) {
	value, provided, err := optionalQueryBool(r, key)
	if err != nil {
		return false, err
	}
	if !provided {
		return defaultValue, nil
	}
	return value, nil
}

func queryOffsetLimit(r *http.Request, maxLimit int) (offset int, limit int, err error) {
	offset = 0
	offsetRaw := strings.TrimSpace(r.URL.Query().Get("offset"))
	if offsetRaw != "" {
		parsedOffset, parseErr := strconv.Atoi(offsetRaw)
		if parseErr != nil {
			return 0, 0, errors.New("invalid offset query parameter")
		}
		if parsedOffset < 0 {
			return 0, 0, errors.New("offset query parameter must be >= 0")
		}
		offset = parsedOffset
	}

	limit = -1
	limitRaw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if limitRaw != "" {
		parsedLimit, parseErr := strconv.Atoi(limitRaw)
		if parseErr != nil {
			return 0, 0, errors.New("invalid limit query parameter")
		}
		if parsedLimit < 0 {
			return 0, 0, errors.New("limit query parameter must be >= 0")
		}
		limit = parsedLimit
	}
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}
	return offset, limit, nil
}

func optionalQueryUint64(r *http.Request, key string) (value uint64, provided bool, err error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return 0, false, nil
	}
	parsed, parseErr := strconv.ParseUint(raw, 10, 64)
	if parseErr != nil {
		return 0, true, fmt.Errorf("invalid %s query parameter", key)
	}
	return parsed, true, nil
}

func optionalQueryInt64(r *http.Request, key string) (value int64, provided bool, err error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return 0, false, nil
	}
	parsed, parseErr := strconv.ParseInt(raw, 10, 64)
	if parseErr != nil {
		return 0, true, fmt.Errorf("invalid %s query parameter", key)
	}
	return parsed, true, nil
}

func optionalQueryBool(r *http.Request, key string) (value bool, provided bool, err error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return false, false, nil
	}
	parsed, parseErr := strconv.ParseBool(raw)
	if parseErr != nil {
		return false, true, fmt.Errorf("invalid %s query parameter", key)
	}
	return parsed, true, nil
}

func paginationBounds(total, offset, limit int) (start int, end int) {
	start = offset
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	if limit < 0 {
		return start, total
	}
	end = start + limit
	if end > total {
		end = total
	}
	if end < start {
		end = start
	}
	return start, end
}

func txKindOrTransfer(tx chain.Transaction) string {
	kind := strings.TrimSpace(tx.Kind)
	if kind == "" {
		return chain.TxKindTransfer
	}
	return kind
}

func findPendingTx(
	pending []chain.PendingTransaction,
	matchFn func(chain.PendingTransaction) bool,
) (chain.PendingTransaction, bool) {
	for idx := len(pending) - 1; idx >= 0; idx-- {
		item := pending[idx]
		if matchFn(item) {
			return item, true
		}
	}
	return chain.PendingTransaction{}, false
}

func findProductProofForAttestation(proofs []chain.ProductProof, tx chain.Transaction) (chain.ProductProof, bool) {
	for _, proof := range proofs {
		if proof.ProofRef != string(tx.To) {
			continue
		}
		if proof.ValidatorID != tx.ValidatorID {
			continue
		}
		if proof.Units != tx.Amount {
			continue
		}
		if proof.QualityBps != tx.BasisPoints {
			continue
		}
		return proof, true
	}
	return chain.ProductProof{}, false
}

func findPendingAttestationForTx(pending []chain.ProductPendingAttestation, tx chain.Transaction) (chain.ProductPendingAttestation, bool) {
	for _, attestation := range pending {
		if attestation.ProofRef != string(tx.To) {
			continue
		}
		if attestation.ValidatorID != tx.ValidatorID {
			continue
		}
		if attestation.Units != tx.Amount {
			continue
		}
		if attestation.QualityBps != tx.BasisPoints {
			continue
		}
		for _, vote := range attestation.Votes {
			if vote.Oracle == tx.From {
				return attestation, true
			}
		}
	}
	return chain.ProductPendingAttestation{}, false
}

func findProductChallengeByID(challenges []chain.ProductChallenge, challengeID string) (chain.ProductChallenge, bool) {
	for _, challenge := range challenges {
		if challenge.ID == challengeID {
			return challenge, true
		}
	}
	return chain.ProductChallenge{}, false
}

func findProductChallengeForProof(challenges []chain.ProductChallenge, proofID string) (chain.ProductChallenge, bool) {
	var selected chain.ProductChallenge
	found := false
	for _, challenge := range challenges {
		if challenge.ProofID != proofID {
			continue
		}
		if challenge.Open {
			return challenge, true
		}
		if !found || challenge.CreatedHeight > selected.CreatedHeight || (challenge.CreatedHeight == selected.CreatedHeight && challenge.CreatedMs > selected.CreatedMs) {
			selected = challenge
			found = true
		}
	}
	return selected, found
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
