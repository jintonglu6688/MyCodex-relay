package host

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

func TestRegisterAndGetHostIsTenantScoped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	if err := service.RegisterHost("tenant_a", "host_same", "Windows A", "public-a"); err != nil {
		t.Fatalf("RegisterHost tenant_a failed: %v", err)
	}
	if err := service.RegisterHost("tenant_b", "host_same", "Windows B", "public-b"); err != nil {
		t.Fatalf("RegisterHost tenant_b failed: %v", err)
	}

	host, err := service.GetHost("tenant_a", "host_same")
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if host.DisplayName != "Windows A" || host.HostPublicKey != "public-a" {
		t.Fatalf("unexpected tenant_a host: %+v", host)
	}
	other, err := service.GetHost("tenant_b", "host_same")
	if err != nil {
		t.Fatalf("GetHost tenant_b failed: %v", err)
	}
	if other.DisplayName != "Windows B" || other.HostPublicKey != "public-b" {
		t.Fatalf("unexpected tenant_b host: %+v", other)
	}
}

func TestHostEnrollmentStoresSigningAndAgreementKeysAndKeyVersion(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	created, _, err := tenant.NewService(st).Create("Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	agreement, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate agreement key: %v", err)
	}
	signingPublic := base64.RawURLEncoding.EncodeToString(
		elliptic.Marshal(elliptic.P256(), signing.X, signing.Y))
	agreementPublic := base64.RawURLEncoding.EncodeToString(
		elliptic.Marshal(elliptic.P256(), agreement.X, agreement.Y))

	enrolled, err := NewService(st).EnrollHost(Enrollment{
		TenantID:           created.TenantID,
		HostID:             "host_a",
		DisplayName:        "Windows",
		SigningPublicKey:   signingPublic,
		AgreementPublicKey: agreementPublic,
		KeyVersion:         7,
	})
	if err != nil {
		t.Fatalf("EnrollHost failed: %v", err)
	}
	loaded, err := NewService(st).GetHost(created.TenantID, "host_a")
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if enrolled.SigningPublicKey != signingPublic ||
		loaded.SigningPublicKey != signingPublic ||
		loaded.AgreementPublicKey != agreementPublic ||
		loaded.KeyVersion != 7 {
		t.Fatalf("unexpected enrolled host: %+v / %+v", enrolled, loaded)
	}

	idempotent, err := NewService(st).EnrollHost(Enrollment{
		TenantID:           created.TenantID,
		HostID:             "host_a",
		DisplayName:        "Renamed Windows",
		SigningPublicKey:   signingPublic,
		AgreementPublicKey: agreementPublic,
		KeyVersion:         7,
	})
	if err != nil {
		t.Fatalf("idempotent EnrollHost failed: %v", err)
	}
	if idempotent.DisplayName != "Renamed Windows" ||
		idempotent.SigningPublicKey != signingPublic ||
		idempotent.AgreementPublicKey != agreementPublic ||
		idempotent.KeyVersion != 7 {
		t.Fatalf("idempotent enrollment changed identity: %+v", idempotent)
	}
}

func TestHostEnrollmentRejectsIdentityReplacementWithoutMutation(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	created, _, err := tenant.NewService(st).Create("Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	signingPublic := newPublicKey(t)
	agreementPublic := newPublicKey(t)
	service := NewService(st)
	request := Enrollment{
		TenantID:           created.TenantID,
		HostID:             "host_a",
		DisplayName:        "Windows",
		SigningPublicKey:   signingPublic,
		AgreementPublicKey: agreementPublic,
		KeyVersion:         7,
	}
	if _, err := service.EnrollHost(request); err != nil {
		t.Fatalf("initial EnrollHost failed: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Enrollment)
	}{
		{"different signing key", func(value *Enrollment) { value.SigningPublicKey = newPublicKey(t) }},
		{"different agreement key", func(value *Enrollment) { value.AgreementPublicKey = newPublicKey(t) }},
		{"lower key version", func(value *Enrollment) { value.KeyVersion = 6 }},
		{"higher key version", func(value *Enrollment) { value.KeyVersion = 8 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			changed.DisplayName = "Attacker rename"
			test.mutate(&changed)
			if _, err := service.EnrollHost(changed); err == nil ||
				err.Error() != "host_identity_conflict_reset_required" {
				t.Fatalf("EnrollHost error = %v, want host_identity_conflict_reset_required", err)
			}
			loaded, err := service.GetHost(request.TenantID, request.HostID)
			if err != nil {
				t.Fatalf("GetHost failed: %v", err)
			}
			if loaded.DisplayName != request.DisplayName ||
				loaded.SigningPublicKey != request.SigningPublicKey ||
				loaded.AgreementPublicKey != request.AgreementPublicKey ||
				loaded.KeyVersion != request.KeyVersion {
				t.Fatalf("rejected enrollment mutated host: %+v", loaded)
			}
		})
	}
}

func TestHostEnrollmentDoesNotUnrevokeHost(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	created, _, err := tenant.NewService(st).Create("Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	request := Enrollment{
		TenantID:           created.TenantID,
		HostID:             "host_a",
		DisplayName:        "Windows",
		SigningPublicKey:   newPublicKey(t),
		AgreementPublicKey: newPublicKey(t),
		KeyVersion:         1,
	}
	service := NewService(st)
	if _, err := service.EnrollHost(request); err != nil {
		t.Fatalf("initial EnrollHost failed: %v", err)
	}
	if _, err := st.DB().Exec(
		"update hosts set revoked = 1 where tenant_id = ? and host_id = ?",
		request.TenantID, request.HostID); err != nil {
		t.Fatalf("revoke host: %v", err)
	}
	if _, err := service.EnrollHost(request); err == nil ||
		err.Error() != "host_identity_conflict_reset_required" {
		t.Fatalf("EnrollHost error = %v, want host_identity_conflict_reset_required", err)
	}
	loaded, err := service.GetHost(request.TenantID, request.HostID)
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if !loaded.Revoked {
		t.Fatal("ordinary enrollment un-revoked host")
	}
}

func TestHostEnrollmentRejectsReusedSigningAndAgreementKey(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	created, _, err := tenant.NewService(st).Create("Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	publicKey := newPublicKey(t)
	if _, err := NewService(st).EnrollHost(Enrollment{
		TenantID:           created.TenantID,
		HostID:             "host_a",
		DisplayName:        "Windows",
		SigningPublicKey:   publicKey,
		AgreementPublicKey: publicKey,
		KeyVersion:         1,
	}); err == nil || err.Error() != "invalid_host_identity" {
		t.Fatalf("EnrollHost error = %v, want invalid_host_identity", err)
	}
	if _, err := NewService(st).GetHost(created.TenantID, "host_a"); err == nil {
		t.Fatal("invalid shared-key enrollment persisted a host")
	}
}

func newPublicKey(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(
		elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y))
}
