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
  host_public_key text not null,
  enabled integer not null,
  registered_at text not null,
  last_seen_at text,
  primary key (tenant_id, host_id),
  foreign key (tenant_id) references tenants(tenant_id)
);

create table if not exists devices (
  tenant_id text not null,
  host_id text not null,
  device_id text not null,
  display_name text not null,
  platform text not null,
  device_public_key text not null,
  device_token_hash text,
  revoked integer not null,
  bound_at text not null,
  last_seen_at text,
  primary key (tenant_id, host_id, device_id)
);

create table if not exists pairing_invites (
  tenant_id text not null,
  host_id text not null,
  invite_id text not null,
  token_hash text not null,
  expires_at text not null,
  consumed_at text,
  max_uses integer not null,
  primary key (tenant_id, host_id, invite_id)
);

create table if not exists audit_events (
  id integer primary key autoincrement,
  tenant_id text,
  event_type text not null,
  message text not null,
  created_at text not null
);
`
