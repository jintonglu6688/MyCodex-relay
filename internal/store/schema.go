package store

const SchemaSQL = `
create table if not exists tenants (
  tenant_id text primary key,
  display_name text not null,
  enabled integer not null,
  secret_hash text not null,
  created_at text not null
);

create table if not exists hosts (
  tenant_id text not null,
  host_id text not null,
  display_name text not null,
  signing_public_key text not null,
  agreement_public_key text not null,
  key_version integer not null,
  enabled integer not null,
  revoked integer not null,
  registered_at text not null,
  last_seen_at text,
  primary key (tenant_id, host_id),
  foreign key (tenant_id) references tenants(tenant_id)
);

create table if not exists devices (
  tenant_id text not null,
  host_id text not null,
  device_id text not null,
  signing_public_key text not null,
  agreement_public_key text not null,
  key_version integer not null,
  binding_version integer not null,
  revoked integer not null,
  approved_at text not null,
  last_seen_at text,
  primary key (tenant_id, host_id, device_id),
  foreign key (tenant_id, host_id) references hosts(tenant_id, host_id)
);

create table if not exists pairing_invites (
  tenant_id text not null,
  host_id text not null,
  invite_id text not null,
  status text not null,
  created_at integer not null,
  expires_at integer not null,
  consumed_at integer,
  primary key (tenant_id, host_id, invite_id),
  foreign key (tenant_id, host_id) references hosts(tenant_id, host_id)
);

create table if not exists pairing_claims (
  claim_id text primary key,
  invite_id text not null,
  tenant_id text not null,
  host_id text not null,
  device_id text not null,
  header_json text not null,
  nonce text not null,
  ciphertext text not null,
  access_token_hash blob not null,
  status text not null,
  device_signing_public_key text,
  device_agreement_public_key text,
  device_key_version integer,
  binding_version integer,
  approval_header text,
  approval_nonce text,
  approval_ciphertext text,
  created_at integer not null,
  updated_at integer not null,
  expires_at integer not null,
  consumed_at integer,
  foreign key (tenant_id, host_id, invite_id)
    references pairing_invites(tenant_id, host_id, invite_id)
);

create table if not exists auth_challenges (
  challenge_id text primary key,
  challenge_hash blob not null,
  protocol_version integer not null,
  relay_fingerprint text not null,
  relay_signature text not null,
  subject_type text not null,
  subject_id text not null,
  tenant_id text not null,
  host_id text not null,
  device_id text not null,
  purpose text not null,
  issued_at integer not null,
  expires_at integer not null,
  consumed_at integer
);

create table if not exists auth_tickets (
  ticket_hash blob primary key,
  subject_type text not null,
  subject_id text not null,
  tenant_id text not null,
  host_id text not null,
  device_id text not null,
  purpose text not null,
  issued_at integer not null,
  expires_at integer not null,
  consumed_at integer
);

create table if not exists audit_events (
  id integer primary key autoincrement,
  tenant_id text,
  event_type text not null,
  message text not null,
  created_at text not null
);
`
