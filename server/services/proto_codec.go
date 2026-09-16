// proto_codec.go — hand-rolled protobuf wire codec for EvidenceChunk and
// ForensicTask using protowire primitives.  Field numbers match forensics.proto.
// This avoids a protoc dependency at build time; swap for generated code once
// protoc is available.
package services

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// ---- EvidenceChunk (field numbers from forensics.proto) -------------------
// field 1 = session_id (string)
// field 2 = task_id    (string)
// field 3 = artifact_type (varint / enum)
// field 4 = chunk_index (varint uint32)
// field 5 = total_chunks (varint uint32)
// field 6 = encrypted_data (bytes)
// field 7 = sha256_checksum (bytes)
// field 8 = collected_at (varint int64)

type EvidenceChunkProto struct {
	SessionID      string
	TaskID         string
	ArtifactType   uint32
	ChunkIndex     uint32
	TotalChunks    uint32
	EncryptedData  []byte
	SHA256Checksum []byte
	CollectedAt    int64
}

func MarshalEvidenceChunk(ec *EvidenceChunkProto) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, ec.SessionID)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, ec.TaskID)
	b = protowire.AppendTag(b, 3, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(ec.ArtifactType))
	b = protowire.AppendTag(b, 4, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(ec.ChunkIndex))
	b = protowire.AppendTag(b, 5, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(ec.TotalChunks))
	if len(ec.EncryptedData) > 0 {
		b = protowire.AppendTag(b, 6, protowire.BytesType)
		b = protowire.AppendBytes(b, ec.EncryptedData)
	}
	if len(ec.SHA256Checksum) > 0 {
		b = protowire.AppendTag(b, 7, protowire.BytesType)
		b = protowire.AppendBytes(b, ec.SHA256Checksum)
	}
	b = protowire.AppendTag(b, 8, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(ec.CollectedAt))
	return b
}

func UnmarshalEvidenceChunk(data []byte) (*EvidenceChunkProto, error) {
	ec := &EvidenceChunkProto{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("EvidenceChunk: bad tag at offset 0: %w", protowire.ParseError(n))
		}
		data = data[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 1: %w", protowire.ParseError(n))
			}
			ec.SessionID = v
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 2: %w", protowire.ParseError(n))
			}
			ec.TaskID = v
			data = data[n:]
		case num == 3 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 3: %w", protowire.ParseError(n))
			}
			ec.ArtifactType = uint32(v)
			data = data[n:]
		case num == 4 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 4: %w", protowire.ParseError(n))
			}
			ec.ChunkIndex = uint32(v)
			data = data[n:]
		case num == 5 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 5: %w", protowire.ParseError(n))
			}
			ec.TotalChunks = uint32(v)
			data = data[n:]
		case num == 6 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 6: %w", protowire.ParseError(n))
			}
			ec.EncryptedData = append([]byte(nil), v...)
			data = data[n:]
		case num == 7 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 7: %w", protowire.ParseError(n))
			}
			ec.SHA256Checksum = append([]byte(nil), v...)
			data = data[n:]
		case num == 8 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk field 8: %w", protowire.ParseError(n))
			}
			ec.CollectedAt = int64(v)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, fmt.Errorf("EvidenceChunk unknown field %d: %w", num, protowire.ParseError(n))
			}
			data = data[n:]
		}
	}
	return ec, nil
}

// ---- ForensicTask (subset — compiled_ir_payload field 8) ------------------
// field 1 = task_id (string)
// field 2 = session_id (string)
// field 4 = target (string)
// field 6 = encryption (varint / enum)
// field 8 = compiled_ir_payload (bytes)
// field 9 = issued_at (int64 varint)

type ForensicTaskProto struct {
	TaskID             string
	SessionID          string
	Target             string
	Encryption         uint32
	CompiledIRPayload  []byte
	IssuedAt           int64
}

func MarshalForensicTask(ft *ForensicTaskProto) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, ft.TaskID)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, ft.SessionID)
	b = protowire.AppendTag(b, 4, protowire.BytesType)
	b = protowire.AppendString(b, ft.Target)
	b = protowire.AppendTag(b, 6, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(ft.Encryption))
	if len(ft.CompiledIRPayload) > 0 {
		b = protowire.AppendTag(b, 8, protowire.BytesType)
		b = protowire.AppendBytes(b, ft.CompiledIRPayload)
	}
	b = protowire.AppendTag(b, 9, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(ft.IssuedAt))
	return b
}

func UnmarshalForensicTask(data []byte) (*ForensicTaskProto, error) {
	ft := &ForensicTaskProto{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("ForensicTask: bad tag: %w", protowire.ParseError(n))
		}
		data = data[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return nil, fmt.Errorf("ForensicTask field 1: %w", protowire.ParseError(n))
			}
			ft.TaskID = v
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return nil, fmt.Errorf("ForensicTask field 2: %w", protowire.ParseError(n))
			}
			ft.SessionID = v
			data = data[n:]
		case num == 4 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(data)
			if n < 0 {
				return nil, fmt.Errorf("ForensicTask field 4: %w", protowire.ParseError(n))
			}
			ft.Target = v
			data = data[n:]
		case num == 6 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("ForensicTask field 6: %w", protowire.ParseError(n))
			}
			ft.Encryption = uint32(v)
			data = data[n:]
		case num == 8 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("ForensicTask field 8: %w", protowire.ParseError(n))
			}
			ft.CompiledIRPayload = append([]byte(nil), v...)
			data = data[n:]
		case num == 9 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("ForensicTask field 9: %w", protowire.ParseError(n))
			}
			ft.IssuedAt = int64(v)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, fmt.Errorf("ForensicTask unknown field %d: %w", num, protowire.ParseError(n))
			}
			data = data[n:]
		}
	}
	return ft, nil
}
