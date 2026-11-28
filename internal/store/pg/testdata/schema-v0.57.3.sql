CREATE TABLE IF NOT EXISTS clearance_evidence (
  seq        bigint PRIMARY KEY,
  hash       text   NOT NULL UNIQUE,
  prev_hash  text   NOT NULL,
  record     jsonb  NOT NULL,
  assurance  text   NOT NULL DEFAULT 'recorded-not-checkpointed'
             CHECK (assurance IN ('checkpointed', 'recorded-not-checkpointed', 'not-recorded')),
  written_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_evidence_receipt ON clearance_evidence
  ((record->'effect'->>'repo'), (record->'effect'->>'pr')) WHERE record ? 'effect';
CREATE INDEX IF NOT EXISTS clearance_evidence_cost ON clearance_evidence (seq)
  WHERE record ? 'usage' OR record ? 'cost';
CREATE TABLE IF NOT EXISTS clearance_changes (
  id         text        PRIMARY KEY,
  app        text        NOT NULL,
  env        text        NOT NULL,
  state      text        NOT NULL,
  repo       text        NOT NULL,
  pr         integer     NOT NULL,
  head       text        NOT NULL,
  expires_at timestamptz NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_changes_pr ON clearance_changes (repo, pr);
CREATE INDEX IF NOT EXISTS clearance_changes_state ON clearance_changes (state, expires_at);
CREATE INDEX IF NOT EXISTS clearance_changes_app ON clearance_changes (app, env, updated_at DESC);
CREATE TABLE IF NOT EXISTS clearance_definitions (
  name       text        NOT NULL,
  state      text        NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, state)
);
CREATE TABLE IF NOT EXISTS clearance_targets (
  source     text        PRIMARY KEY,
  digest     text        NOT NULL,
  doc        jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS clearance_protection (
  cluster     text        PRIMARY KEY,
  digest      text        NOT NULL,
  doc         jsonb       NOT NULL,
  reported_at timestamptz NOT NULL DEFAULT now(),
  changed_at  timestamptz NOT NULL DEFAULT now(),
  seq          bigint      NOT NULL DEFAULT 0,
  window_start timestamptz NOT NULL DEFAULT 'epoch',
  window_count integer     NOT NULL DEFAULT 0,
  add_count    integer     NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clearance_tokens (
  change_id  text        PRIMARY KEY,
  cluster    text        NOT NULL,
  nonce      text        NOT NULL,
  key_id     text        NOT NULL,
  issued_at  timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  envelope   jsonb       NOT NULL,
  jwt        text        NOT NULL
);
CREATE INDEX IF NOT EXISTS clearance_tokens_feed ON clearance_tokens (cluster, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS clearance_tokens_due ON clearance_tokens (expires_at) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS clearance_signing_keys (
  key_id     text        PRIMARY KEY,
  jwk        jsonb       NOT NULL,
  created_at timestamptz NOT NULL,
  retired_at timestamptz
);
ALTER TABLE clearance_signing_keys ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
CREATE TABLE IF NOT EXISTS clearance_attestations (
  change_id       text        PRIMARY KEY,
  digest          text        NOT NULL,
  backend         text        NOT NULL,
  key_id          text        NOT NULL,
  rekor_log_index bigint,
  rekor_uuid      text        NOT NULL,
  outcome_seq     bigint      NOT NULL,
  record_seq      bigint      NOT NULL,
  created_at      timestamptz NOT NULL,
  bundle          jsonb       NOT NULL
);
CREATE TABLE IF NOT EXISTS clearance_feeds (
  cluster    text        PRIMARY KEY,
  seq        bigint      NOT NULL,
  key_id     text        NOT NULL,
  issued_at  timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  envelope   jsonb       NOT NULL,
  tokens     jsonb       NOT NULL
);
CREATE INDEX IF NOT EXISTS clearance_evidence_app ON clearance_evidence ((record->>'principal'), seq)
  WHERE record->>'principal' LIKE 'app:%';
CREATE TABLE IF NOT EXISTS clearance_tree_people (
  key        text        PRIMARY KEY,
  target     text        NOT NULL DEFAULT '',
  has_source boolean     NOT NULL DEFAULT false,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_tree_people_window ON clearance_tree_people (target, updated_at) WHERE has_source;
CREATE TABLE IF NOT EXISTS clearance_breakglass (
  id         text        PRIMARY KEY,
  cluster    text        NOT NULL,
  env        text        NOT NULL,
  state      text        NOT NULL CHECK (state IN ('open', 'closed')),
  expires_at timestamptz NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_breakglass_open ON clearance_breakglass (expires_at) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS clearance_evidence_exceptions ON clearance_evidence (seq)
  WHERE record->>'tool' IN ('deploy.exception', 'deploy.degraded', 'breakglass.open', 'breakglass.close')
     OR record->>'coverage' = 'coverage-unavailable';
CREATE INDEX IF NOT EXISTS clearance_evidence_event ON clearance_evidence
  ((record->'provider'->>'name'), (record->>'tool'), (record->'source'->>'event_id'))
  WHERE record->'source' ? 'event_id';
CREATE INDEX IF NOT EXISTS clearance_evidence_observed ON clearance_evidence ((record->>'scope'), seq)
  WHERE record->>'tool' IN ('observation', 'assessment', 'resolution', 'observation.health', 'observation.audit-gap');
CREATE INDEX IF NOT EXISTS clearance_evidence_verification ON clearance_evidence ((record->>'scope'), seq)
  WHERE record->>'tool' = 'observation.verification';
CREATE INDEX IF NOT EXISTS clearance_evidence_written ON clearance_evidence (written_at);
CREATE TABLE IF NOT EXISTS clearance_ledger_checkpoints (
  size   bigint      PRIMARY KEY,
  origin text        NOT NULL,
  root   text        NOT NULL,
  note   bytea       NOT NULL,
  at     timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS clearance_evidence_change ON clearance_evidence ((record->'change'->>'id'), seq)
  WHERE record->>'tool' LIKE 'deploy.%';
CREATE INDEX IF NOT EXISTS clearance_attestations_seq ON clearance_attestations (record_seq DESC);
CREATE TABLE IF NOT EXISTS clearance_packets (
  id         text        PRIMARY KEY,
  digest     text        NOT NULL,
  size       bigint      NOT NULL,
  meta       jsonb       NOT NULL,
  bundle     bytea       NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
