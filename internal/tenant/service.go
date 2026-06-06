package tenant

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/mycodex/mycodex-relay/internal/security"
	"github.com/mycodex/mycodex-relay/internal/store"
)

type Tenant struct {
	TenantID    string
	DisplayName string
	Enabled     bool
	SecretHash  string
	CreatedAt   time.Time
}

type Service struct {
	store *store.Store
}

func NewService(store *store.Store) *Service {
	return &Service{store: store}
}

func VerifySecretHash(hash string, secret string) bool {
	return security.VerifySecret(hash, secret)
}

func (s *Service) Create(displayName string) (Tenant, string, error) {
	name := strings.TrimSpace(displayName)
	if name == "" {
		return Tenant{}, "", fmt.Errorf("display name cannot be empty")
	}
	tenantID, err := randomID("tenant")
	if err != nil {
		return Tenant{}, "", err
	}
	secret, err := security.GenerateToken(32)
	if err != nil {
		return Tenant{}, "", err
	}
	hash, err := security.HashSecret(secret)
	if err != nil {
		return Tenant{}, "", err
	}
	now := time.Now().UTC()
	_, err = s.store.DB().Exec(
		"insert into tenants (tenant_id, display_name, enabled, secret_hash, created_at) values (?, ?, ?, ?, ?)",
		tenantID, name, 1, hash, now.Format(time.RFC3339Nano))
	if err != nil {
		return Tenant{}, "", err
	}
	return Tenant{TenantID: tenantID, DisplayName: name, Enabled: true, SecretHash: hash, CreatedAt: now}, secret, nil
}

func (s *Service) Get(tenantID string) (Tenant, error) {
	row := s.store.DB().QueryRow(
		"select tenant_id, display_name, enabled, secret_hash, created_at from tenants where tenant_id = ?",
		tenantID)
	var tenant Tenant
	var enabled int
	var created string
	if err := row.Scan(&tenant.TenantID, &tenant.DisplayName, &enabled, &tenant.SecretHash, &created); err != nil {
		if err == sql.ErrNoRows {
			return Tenant{}, fmt.Errorf("tenant_not_found")
		}
		return Tenant{}, err
	}
	tenant.Enabled = enabled != 0
	tenant.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return tenant, nil
}

func (s *Service) List() ([]Tenant, error) {
	rows, err := s.store.DB().Query(
		"select tenant_id, display_name, enabled, secret_hash, created_at from tenants order by created_at, tenant_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []Tenant
	for rows.Next() {
		var tenant Tenant
		var enabled int
		var created string
		if err := rows.Scan(&tenant.TenantID, &tenant.DisplayName, &enabled, &tenant.SecretHash, &created); err != nil {
			return nil, err
		}
		tenant.Enabled = enabled != 0
		tenant.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

func (s *Service) SetEnabled(tenantID string, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	result, err := s.store.DB().Exec("update tenants set enabled = ? where tenant_id = ?", value, tenantID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("tenant_not_found")
	}
	return nil
}

func (s *Service) RotateSecret(tenantID string) (string, error) {
	secret, err := security.GenerateToken(32)
	if err != nil {
		return "", err
	}
	hash, err := security.HashSecret(secret)
	if err != nil {
		return "", err
	}
	result, err := s.store.DB().Exec("update tenants set secret_hash = ? where tenant_id = ?", hash, tenantID)
	if err != nil {
		return "", err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if rows == 0 {
		return "", fmt.Errorf("tenant_not_found")
	}
	return secret, nil
}

func randomID(prefix string) (string, error) {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}
