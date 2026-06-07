package pairing

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mycodex/mycodex-relay/internal/store"
)

func TestInviteCreateAndClaim(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	invite, token, err := service.CreateInvite("tenant_a", "host_a", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateInvite failed: %v", err)
	}
	claim, err := service.ClaimInvite(ClaimRequest{
		TenantID:          "tenant_a",
		HostID:            "host_a",
		InviteID:          invite.InviteID,
		Token:             token,
		DeviceID:          "device_a",
		DeviceDisplayName: "Android",
		DevicePublicKey:   "public-key",
		Platform:          "android",
	})
	if err != nil {
		t.Fatalf("ClaimInvite failed: %v", err)
	}
	if claim.DeviceID != "device_a" {
		t.Fatalf("unexpected claim: %+v", claim)
	}
}

func TestInviteCannotBeClaimedTwice(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	invite, token, err := service.CreateInvite("tenant_a", "host_a", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateInvite failed: %v", err)
	}
	request := ClaimRequest{TenantID: "tenant_a", HostID: "host_a", InviteID: invite.InviteID, Token: token, DeviceID: "device_a", DeviceDisplayName: "Android", DevicePublicKey: "public-key", Platform: "android"}
	if _, err := service.ClaimInvite(request); err != nil {
		t.Fatalf("first claim failed: %v", err)
	}
	if _, err := service.ClaimInvite(request); err == nil || err.Error() != "invite_consumed" {
		t.Fatalf("expected invite_consumed, got %v", err)
	}
}

func TestBindInviteConsumesInviteAndPersistsDeviceToken(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	invite, token, err := service.CreateInvite("tenant_a", "host_a", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateInvite failed: %v", err)
	}
	result, err := service.BindInvite(ClaimRequest{
		TenantID:          "tenant_a",
		HostID:            "host_a",
		InviteID:          invite.InviteID,
		Token:             token,
		DeviceID:          "device_a",
		DeviceDisplayName: "Android",
		DevicePublicKey:   "public-key",
		Platform:          "android",
	})
	if err != nil {
		t.Fatalf("BindInvite failed: %v", err)
	}
	if result.Claim.DeviceID != "device_a" || result.DeviceToken == "" {
		t.Fatalf("unexpected bind result: %+v", result)
	}
	if !service.VerifyDeviceToken("tenant_a", "host_a", "device_a", result.DeviceToken) {
		t.Fatalf("expected bound device token to verify")
	}
	device, err := service.GetDevice("tenant_a", "host_a", "device_a")
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if device.DisplayName != "Android" || device.Platform != "android" {
		t.Fatalf("unexpected device: %+v", device)
	}
	if _, err := service.ClaimInvite(ClaimRequest{
		TenantID:          "tenant_a",
		HostID:            "host_a",
		InviteID:          invite.InviteID,
		Token:             token,
		DeviceID:          "device_b",
		DeviceDisplayName: "Android",
		DevicePublicKey:   "public-key",
		Platform:          "android",
	}); err == nil || err.Error() != "invite_consumed" {
		t.Fatalf("expected consumed invite after bind, got %v", err)
	}
}
