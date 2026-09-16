package services

import (
	"bytes"
	"testing"
	"time"
)

func TestEvidenceChunkRoundtrip(t *testing.T) {
	original := &EvidenceChunkProto{
		SessionID:      "sess-abc123",
		TaskID:         "task-xyz",
		ArtifactType:   3, // ARTIFACT_NETWORK
		ChunkIndex:     0,
		TotalChunks:    5,
		EncryptedData:  []byte("encrypted-payload-data"),
		SHA256Checksum: []byte("sha256checksum32bytesxxxxxxxxx!!"),
		CollectedAt:    time.Now().Unix(),
	}

	encoded := MarshalEvidenceChunk(original)
	if len(encoded) == 0 {
		t.Fatal("MarshalEvidenceChunk produced empty output")
	}

	decoded, err := UnmarshalEvidenceChunk(encoded)
	if err != nil {
		t.Fatalf("UnmarshalEvidenceChunk error: %v", err)
	}

	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID: want %q got %q", original.SessionID, decoded.SessionID)
	}
	if decoded.TaskID != original.TaskID {
		t.Errorf("TaskID: want %q got %q", original.TaskID, decoded.TaskID)
	}
	if decoded.ArtifactType != original.ArtifactType {
		t.Errorf("ArtifactType: want %d got %d", original.ArtifactType, decoded.ArtifactType)
	}
	if decoded.ChunkIndex != original.ChunkIndex {
		t.Errorf("ChunkIndex: want %d got %d", original.ChunkIndex, decoded.ChunkIndex)
	}
	if decoded.TotalChunks != original.TotalChunks {
		t.Errorf("TotalChunks: want %d got %d", original.TotalChunks, decoded.TotalChunks)
	}
	if !bytes.Equal(decoded.EncryptedData, original.EncryptedData) {
		t.Errorf("EncryptedData mismatch")
	}
	if !bytes.Equal(decoded.SHA256Checksum, original.SHA256Checksum) {
		t.Errorf("SHA256Checksum mismatch")
	}
	if decoded.CollectedAt != original.CollectedAt {
		t.Errorf("CollectedAt: want %d got %d", original.CollectedAt, decoded.CollectedAt)
	}
}

func TestForensicTaskRoundtrip(t *testing.T) {
	original := &ForensicTaskProto{
		TaskID:            "task-001",
		SessionID:         "sess-001",
		Target:            "192.168.1.100",
		Encryption:        1, // ENCRYPTION_AES256_GCM
		CompiledIRPayload: []byte("; compiled LLVM IR payload"),
		IssuedAt:          time.Now().Unix(),
	}

	encoded := MarshalForensicTask(original)
	if len(encoded) == 0 {
		t.Fatal("MarshalForensicTask produced empty output")
	}

	decoded, err := UnmarshalForensicTask(encoded)
	if err != nil {
		t.Fatalf("UnmarshalForensicTask error: %v", err)
	}

	if decoded.TaskID != original.TaskID {
		t.Errorf("TaskID: want %q got %q", original.TaskID, decoded.TaskID)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID: want %q got %q", original.SessionID, decoded.SessionID)
	}
	if decoded.Target != original.Target {
		t.Errorf("Target: want %q got %q", original.Target, decoded.Target)
	}
	if decoded.Encryption != original.Encryption {
		t.Errorf("Encryption: want %d got %d", original.Encryption, decoded.Encryption)
	}
	if !bytes.Equal(decoded.CompiledIRPayload, original.CompiledIRPayload) {
		t.Errorf("CompiledIRPayload mismatch")
	}
	if decoded.IssuedAt != original.IssuedAt {
		t.Errorf("IssuedAt: want %d got %d", original.IssuedAt, decoded.IssuedAt)
	}
}

func TestUnmarshalCorruptedBytesReturnsError(t *testing.T) {
	corrupt := []byte{0xFF, 0xFE, 0x00, 0xAB, 0xCD}
	_, err := UnmarshalEvidenceChunk(corrupt)
	if err == nil {
		t.Fatal("expected error for corrupted bytes, got nil")
	}
}

func TestEvidenceChunkEmptyFields(t *testing.T) {
	original := &EvidenceChunkProto{
		SessionID:   "sess-empty",
		ChunkIndex:  0,
		TotalChunks: 1,
	}
	encoded := MarshalEvidenceChunk(original)
	decoded, err := UnmarshalEvidenceChunk(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID mismatch")
	}
	if len(decoded.EncryptedData) != 0 {
		t.Errorf("expected empty EncryptedData, got %d bytes", len(decoded.EncryptedData))
	}
}
