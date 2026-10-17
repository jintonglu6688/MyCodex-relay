package relay

import (
	"net/http"
	"strings"
	"time"

	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	"github.com/mycodex/mycodex-relay/internal/pairing"
	"github.com/mycodex/mycodex-relay/internal/protocol"
)

func (s *Server) registerPairingRoutes() {
	s.mux.HandleFunc("POST /v1/pairing/invites", s.handleCreateInvite)
	s.mux.HandleFunc("POST /v1/pairing/invites/{inviteId}/cancel", s.handleCancelInvite)
	s.mux.HandleFunc("POST /v1/pairing/claims", s.handleSubmitClaim)
	s.mux.HandleFunc("GET /v1/pairing/claims/{claimId}", s.handleGetClaim)
	s.mux.HandleFunc("POST /v1/pairing/claims/{claimId}/cancel", s.handleCancelClaim)
	s.mux.HandleFunc("GET /v1/hosts/{hostId}/pairing/claims", s.handleListPairingClaims)
	s.mux.HandleFunc(
		"POST /v1/hosts/{hostId}/pairing/claims/{claimId}/approve",
		s.handleApprovePairingClaim)
	s.mux.HandleFunc(
		"POST /v1/hosts/{hostId}/pairing/claims/{claimId}/reject",
		s.handleRejectPairingClaim)
	s.mux.HandleFunc("GET /v1/hosts/{hostId}/devices", s.handleListDevices)
	s.mux.HandleFunc(
		"POST /v1/hosts/{hostId}/devices/{deviceId}/revoke",
		s.handleRevokeDevice)
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TenantID  string `json:"tenantId"`
		HostID    string `json:"hostId"`
		InviteID  string `json:"inviteId"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	if !s.authorizeTicket(w, r, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   request.HostID,
		TenantID:    request.TenantID,
		HostID:      request.HostID,
		Purpose:     authsvc.PurposePairingInviteCreate,
	}) {
		return
	}
	if err := pairing.NewService(s.store).CreateInvite(
		request.TenantID,
		request.HostID,
		request.InviteID,
		time.UnixMilli(request.ExpiresAt)); err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pairing.Invite{
		TenantID:  request.TenantID,
		HostID:    request.HostID,
		InviteID:  request.InviteID,
		Status:    pairing.ClaimPending,
		ExpiresAt: request.ExpiresAt,
	})
}

func (s *Server) handleCancelInvite(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenantId")
	hostID := r.URL.Query().Get("hostId")
	inviteID := r.PathValue("inviteId")
	if !s.authorizeTicket(w, r, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   hostID,
		TenantID:    tenantID,
		HostID:      hostID,
		Purpose:     authsvc.PurposePairingInviteCancel,
	}) {
		return
	}
	if err := pairing.NewService(s.store).CancelInvite(tenantID, hostID, inviteID); err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inviteId": inviteID,
		"status":   pairing.ClaimCancelled,
	})
}

func (s *Server) handleSubmitClaim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request pairing.SubmitClaimRequest
	if !s.readJSON(w, r, &request) {
		return
	}
	created, err := pairing.NewService(s.store).SubmitClaim(request)
	if err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, created)
}

func (s *Server) handleGetClaim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return
	}
	claim, err := pairing.NewService(s.store).GetClaimWithToken(
		r.PathValue("claimId"),
		token)
	if err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (s *Server) handleCancelClaim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return
	}
	claimID := r.PathValue("claimId")
	if err := pairing.NewService(s.store).CancelClaim(claimID, token); err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"claimId": claimID,
		"status":  pairing.ClaimCancelled,
	})
}

func (s *Server) handleListPairingClaims(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tenantID := r.URL.Query().Get("tenantId")
	hostID := r.PathValue("hostId")
	if !s.authorizeTicket(w, r, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   hostID,
		TenantID:    tenantID,
		HostID:      hostID,
		Purpose:     authsvc.PurposePairingClaimList,
	}) {
		return
	}
	claims, err := pairing.NewService(s.store).ListPendingClaims(tenantID, hostID)
	if err != nil {
		writePairingError(w, err)
		return
	}
	if claims == nil {
		claims = make([]pairing.OpaqueClaim, 0)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"claims": claims})
}

func (s *Server) handleApprovePairingClaim(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenantId")
	hostID := r.PathValue("hostId")
	claimID := r.PathValue("claimId")
	var request pairing.ApproveClaimRequest
	if !s.readJSON(w, r, &request) {
		return
	}
	service := pairing.NewService(s.store)
	deviceID, err := service.ClaimDeviceID(tenantID, hostID, claimID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return
	}
	if !s.authorizeTicket(w, r, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   hostID,
		TenantID:    tenantID,
		HostID:      hostID,
		DeviceID:    deviceID,
		Purpose:     authsvc.PurposePairingClaimApprove,
	}) {
		return
	}
	request.TenantID = tenantID
	request.HostID = hostID
	request.ClaimID = claimID
	if err := service.ApproveClaim(request); err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"claimId": claimID,
		"status":  pairing.ClaimApproved,
	})
}

func (s *Server) handleRejectPairingClaim(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenantId")
	hostID := r.PathValue("hostId")
	claimID := r.PathValue("claimId")
	service := pairing.NewService(s.store)
	deviceID, err := service.ClaimDeviceID(tenantID, hostID, claimID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return
	}
	if !s.authorizeTicket(w, r, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   hostID,
		TenantID:    tenantID,
		HostID:      hostID,
		DeviceID:    deviceID,
		Purpose:     authsvc.PurposePairingClaimReject,
	}) {
		return
	}
	if err := service.RejectClaim(tenantID, hostID, claimID); err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"claimId": claimID,
		"status":  pairing.ClaimRejected,
	})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenantId")
	hostID := r.PathValue("hostId")
	if !s.authorizeTicket(w, r, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   hostID,
		TenantID:    tenantID,
		HostID:      hostID,
		Purpose:     authsvc.PurposeDeviceList,
	}) {
		return
	}
	devices, err := pairing.NewService(s.store).ListDevices(tenantID, hostID)
	if err != nil {
		writePairingError(w, err)
		return
	}
	type deviceResponse struct {
		TenantID                 string `json:"tenantId"`
		HostID                   string `json:"hostId"`
		DeviceID                 string `json:"deviceId"`
		DeviceSigningPublicKey   string `json:"deviceSigningPublicKey"`
		DeviceAgreementPublicKey string `json:"deviceAgreementPublicKey"`
		DeviceKeyVersion         int64  `json:"deviceKeyVersion"`
		BindingVersion           int64  `json:"bindingVersion"`
		Revoked                  bool   `json:"revoked"`
		ApprovedAt               int64  `json:"approvedAt"`
		LastSeenAt               *int64 `json:"lastSeenAt"`
		Online                   bool   `json:"online"`
	}
	response := make([]deviceResponse, 0, len(devices))
	for _, device := range devices {
		var lastSeenAt *int64
		if device.LastSeenAt != nil {
			value := device.LastSeenAt.UnixMilli()
			lastSeenAt = &value
		}
		response = append(response, deviceResponse{
			TenantID:                 device.TenantID,
			HostID:                   device.HostID,
			DeviceID:                 device.DeviceID,
			DeviceSigningPublicKey:   device.SigningPublicKey,
			DeviceAgreementPublicKey: device.AgreementPublicKey,
			DeviceKeyVersion:         device.KeyVersion,
			BindingVersion:           device.BindingVersion,
			Revoked:                  device.Revoked,
			ApprovedAt:               device.ApprovedAt.UnixMilli(),
			LastSeenAt:               lastSeenAt,
			Online: s.isDeviceOnline(
				device.TenantID,
				device.HostID,
				device.DeviceID),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": response})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenantId")
	hostID := r.PathValue("hostId")
	deviceID := r.PathValue("deviceId")
	if !s.authorizeTicket(w, r, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   hostID,
		TenantID:    tenantID,
		HostID:      hostID,
		DeviceID:    deviceID,
		Purpose:     authsvc.PurposeDeviceRevoke,
	}) {
		return
	}
	if err := s.revokeDevice(tenantID, hostID, deviceID); err != nil {
		writePairingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenantId": tenantID,
		"hostId":   hostID,
		"deviceId": deviceID,
		"revoked":  true,
	})
}

func writePairingError(w http.ResponseWriter, err error) {
	code := safePairingErrorCode(err)
	status := http.StatusBadRequest
	switch code {
	case "unauthorized":
		status = http.StatusUnauthorized
	case "invite_not_found", "claim_not_found", "device_not_found":
		status = http.StatusNotFound
	case "invite_exists", "invite_not_pending", "claim_exists",
		"claim_not_pending", "approval_conflict", "device_binding_conflict":
		status = http.StatusConflict
	case "internal_error":
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, protocol.ErrorPayload{Code: code})
}

func safePairingErrorCode(err error) string {
	if err == nil {
		return "internal_error"
	}
	switch strings.TrimSpace(err.Error()) {
	case "invalid_invite",
		"host_not_found",
		"invite_exists",
		"invite_not_found",
		"invite_not_pending",
		"invalid_claim",
		"claim_exists",
		"claim_not_found",
		"claim_not_pending",
		"invalid_device_identity",
		"invalid_approval",
		"approval_conflict",
		"device_binding_conflict",
		"device_not_found",
		"device_revoked",
		"unauthorized":
		return strings.TrimSpace(err.Error())
	default:
		return "internal_error"
	}
}
