package pairing

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mycodex/mycodex-relay/internal/store"
)

func TestApproveClaimPersistsAndRevokesDevice(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	claim := Claim{
		TenantID:          "tenant_a",
		HostID:            "host_a",
		DeviceID:          "device_a",
		DeviceDisplayName: "Android",
		DevicePublicKey:   "device-public",
		Platform:          "android",
	}
	if err := service.ApproveClaim(claim); err != nil {
		t.Fatalf("ApproveClaim failed: %v", err)
	}
	device, err := service.GetDevice("tenant_a", "host_a", "device_a")
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if device.DisplayName != "Android" || device.Revoked {
		t.Fatalf("unexpected device: %+v", device)
	}
	if err := service.RevokeDevice("tenant_a", "host_a", "device_a"); err != nil {
		t.Fatalf("RevokeDevice failed: %v", err)
	}
	if _, err := service.GetDevice("tenant_a", "host_a", "device_a"); err == nil || err.Error() != "device_revoked" {
		t.Fatalf("expected device_revoked, got %v", err)
	}
}

func TestDevicesAreTenantAndHostScoped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	if err := service.ApproveClaim(Claim{TenantID: "tenant_a", HostID: "host_a", DeviceID: "device_same", DeviceDisplayName: "A", DevicePublicKey: "key-a", Platform: "android"}); err != nil {
		t.Fatalf("ApproveClaim tenant_a failed: %v", err)
	}
	if err := service.ApproveClaim(Claim{TenantID: "tenant_b", HostID: "host_a", DeviceID: "device_same", DeviceDisplayName: "B", DevicePublicKey: "key-b", Platform: "android"}); err != nil {
		t.Fatalf("ApproveClaim tenant_b failed: %v", err)
	}

	device, err := service.GetDevice("tenant_a", "host_a", "device_same")
	if err != nil {
		t.Fatalf("GetDevice tenant_a failed: %v", err)
	}
	if device.DisplayName != "A" {
		t.Fatalf("unexpected tenant_a device: %+v", device)
	}
	other, err := service.GetDevice("tenant_b", "host_a", "device_same")
	if err != nil {
		t.Fatalf("GetDevice tenant_b failed: %v", err)
	}
	if other.DisplayName != "B" {
		t.Fatalf("unexpected tenant_b device: %+v", other)
	}
	if _, err := service.GetDevice("tenant_a", "host_b", "device_same"); err == nil || err.Error() != "device_not_found" {
		t.Fatalf("expected host-scoped device_not_found, got %v", err)
	}
}

func TestInviteConcurrentClaimsAllowOnlyOneSuccess(t *testing.T) {
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

	var wait sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := service.ClaimInvite(ClaimRequest{
				TenantID:          "tenant_a",
				HostID:            "host_a",
				InviteID:          invite.InviteID,
				Token:             token,
				DeviceID:          "device_a",
				DeviceDisplayName: "Android",
				DevicePublicKey:   "public-key",
				Platform:          "android",
			})
			results <- err
		}(i)
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	consumed := 0
	var errorTexts []string
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		errorTexts = append(errorTexts, err.Error())
		if err.Error() == "invite_consumed" {
			consumed++
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatalf("expected one success and one invite_consumed, got successes=%d consumed=%d errors=%v", successes, consumed, errorTexts)
	}
}
