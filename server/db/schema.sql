-- JOCKY Forensics Platform — PostgreSQL Database Schema
-- Compliance: Section 69 IT Act 2000 & NTRO Act 2004 Audit Mandates

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS warrants (
    id VARCHAR(64) PRIMARY KEY, -- Format: NTRO-YYYY-TYPE-NNNN
    jurisdiction VARCHAR(128) NOT NULL,
    authorized_by_1 VARCHAR(128) NOT NULL,
    authorized_by_2 VARCHAR(128) NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    signature BYTEA NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    operating_system VARCHAR(32) NOT NULL,
    kernel_version VARCHAR(128) NOT NULL,
    public_key BYTEA NOT NULL,
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(32) DEFAULT 'OFFLINE'
);

CREATE TABLE IF NOT EXISTS forensic_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    warrant_id VARCHAR(64) REFERENCES warrants(id),
    target_ip INET NOT NULL,
    agent_id VARCHAR(64) REFERENCES agents(id),
    status VARCHAR(32) DEFAULT 'PENDING',
    encryption_algorithm VARCHAR(32) NOT NULL,
    key_source VARCHAR(64) NOT NULL,
    transmit_endpoint VARCHAR(255) NOT NULL,
    dsl_source TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS evidence_chunks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES forensic_sessions(id),
    artifact_type VARCHAR(64) NOT NULL,
    chunk_index INT NOT NULL,
    total_chunks INT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    storage_path VARCHAR(512) NOT NULL,
    encrypted_size BIGINT NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log_ledger (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID,
    warrant_id VARCHAR(64),
    event_type VARCHAR(64) NOT NULL,
    officer_id VARCHAR(128),
    details JSONB NOT NULL,
    prev_block_hash VARCHAR(64) NOT NULL,
    block_hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
