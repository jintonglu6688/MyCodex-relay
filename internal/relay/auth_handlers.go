package relay

import (
	"net"
	"net/http"
	"strings"
	"time"

	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	hostsvc "github.com/mycodex/mycodex-relay/internal/host"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/security"
)

const maxChallengeSources = 1024

type challengeAttempt struct {
	windowStart time.Time
	count       int
}

func (s *Server) ensureAuth() error {
	s.authOnce.Do(func() {
		s.identity, s.authErr = security.LoadOrCreateRelayIdentity(s.config.StatePath + ".identity.pk8")
		if s.authErr == nil && s.store != nil {
			s.authService = authsvc.NewService(s.store, s.identity)
		}
	})
	return s.authErr
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	if err := s.ensureAuth(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, protocol.ErrorPayload{Code: "auth_unavailable"})
		return
	}
	identity := s.identity.Public()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"protocolVersion":       authsvc.ProtocolVersion,
		"signingPublicKey":      identity.PublicKeyBase64URL,
		"signingKeyFingerprint": identity.FingerprintBase64URL,
		"serverTime":            time.Now().UTC().UnixMilli(),
		"maxRequestBytes":       s.config.DefaultQuota.MaxMessageBytes,
		"maxMessageBytes":       s.config.DefaultQuota.MaxMessageBytes,
	})
}

func (s *Server) handleEnrollHost(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		TenantID           string `json:"tenantId"`
		HostID             string `json:"hostId"`
		DisplayName        string `json:"displayName"`
		SigningPublicKey   string `json:"signingPublicKey"`
		AgreementPublicKey string `json:"agreementPublicKey"`
		KeyVersion         int64  `json:"keyVersion"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	if !s.authorizeTenant(w, r, request.TenantID) {
		return
	}
	enrolled, err := hostsvc.NewService(s.store).EnrollHost(hostsvc.Enrollment{
		TenantID:           request.TenantID,
		HostID:             request.HostID,
		DisplayName:        request.DisplayName,
		SigningPublicKey:   request.SigningPublicKey,
		AgreementPublicKey: request.AgreementPublicKey,
		KeyVersion:         request.KeyVersion,
	})
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "host_identity_conflict_reset_required" {
			status = http.StatusConflict
		}
		writeJSON(w, status, protocol.ErrorPayload{Code: safeAuthErrorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenantId":   enrolled.TenantID,
		"hostId":     enrolled.HostID,
		"keyVersion": enrolled.KeyVersion,
	})
}

func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	if !s.allowChallenge(r) {
		writeJSON(w, http.StatusTooManyRequests, protocol.ErrorPayload{Code: "rate_limited"})
		return
	}
	var request authsvc.ChallengeRequest
	if !s.readJSON(w, r, &request) {
		return
	}
	if err := s.ensureAuth(); err != nil || s.authService == nil {
		writeJSON(w, http.StatusServiceUnavailable, protocol.ErrorPayload{Code: "auth_unavailable"})
		return
	}
	challenge, err := s.authService.CreateChallenge(request)
	if err != nil {
		writeJSON(w, authErrorStatus(err), protocol.ErrorPayload{Code: safeAuthErrorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, challenge)
}

func (s *Server) handleProve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request authsvc.ProofRequest
	if !s.readJSON(w, r, &request) {
		return
	}
	if err := s.ensureAuth(); err != nil || s.authService == nil {
		writeJSON(w, http.StatusServiceUnavailable, protocol.ErrorPayload{Code: "auth_unavailable"})
		return
	}
	ticket, err := s.authService.Prove(request)
	if err != nil {
		writeJSON(w, authErrorStatus(err), protocol.ErrorPayload{Code: safeAuthErrorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

func (s *Server) authorizeTicket(
	w http.ResponseWriter,
	r *http.Request,
	scope authsvc.TicketScope,
) bool {
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return false
	}
	if err := s.ensureAuth(); err != nil || s.authService == nil {
		writeJSON(w, http.StatusServiceUnavailable, protocol.ErrorPayload{Code: "auth_unavailable"})
		return false
	}
	if err := s.authService.ConsumeTicket(token, scope); err != nil {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return false
	}
	return true
}

func (s *Server) allowChallenge(r *http.Request) bool {
	limit := s.config.DefaultQuota.PairingAttemptsPerMinute
	if limit <= 0 {
		return false
	}
	address := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		address = host
	}
	now := time.Now().UTC()
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	for source, attempt := range s.challengeAttempts {
		if now.Sub(attempt.windowStart) >= time.Minute {
			delete(s.challengeAttempts, source)
		}
	}
	attempt := s.challengeAttempts[address]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) >= time.Minute {
		if _, exists := s.challengeAttempts[address]; !exists &&
			len(s.challengeAttempts) >= maxChallengeSources {
			return false
		}
		attempt = challengeAttempt{windowStart: now}
	}
	if attempt.count >= limit {
		s.challengeAttempts[address] = attempt
		return false
	}
	attempt.count++
	s.challengeAttempts[address] = attempt
	return true
}

func authErrorStatus(err error) int {
	switch safeAuthErrorCode(err) {
	case "auth_unavailable":
		return http.StatusServiceUnavailable
	case "subject_not_found", "invalid_proof", "invalid_challenge",
		"challenge_expired", "challenge_consumed", "invalid_ticket":
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

func safeAuthErrorCode(err error) string {
	if err == nil {
		return "internal_error"
	}
	switch strings.TrimSpace(err.Error()) {
	case "auth_unavailable",
		"invalid_host_enrollment",
		"invalid_host_identity",
		"tenant_not_found",
		"host_identity_conflict_reset_required",
		"invalid_scope",
		"invalid_purpose",
		"invalid_subject_type",
		"subject_not_found",
		"invalid_proof",
		"invalid_challenge",
		"challenge_expired",
		"challenge_consumed",
		"invalid_ticket":
		return strings.TrimSpace(err.Error())
	default:
		return "internal_error"
	}
}
