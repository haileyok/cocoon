package models

import "time"

// SpaceRepo is the latest observed state of one author's repo in a space.
// Space and Author are the repo identity; Rev and LtHash describe its latest
// observed commit. LtHash contains the serialized 2,048-byte LtHash state, not
// the SHA-256 digest exposed by the wire API.
type SpaceRepo struct {
	Space  string `gorm:"primaryKey;index:idx_space_repos_space_author"`
	Author string `gorm:"primaryKey;index:idx_space_repos_space_author"`

	Rev    string `gorm:"index:idx_space_repos_rev,sort:desc"`
	LtHash []byte `gorm:"not null"`

	Status    string     `gorm:"index:idx_space_repos_status"`
	Deleted   bool       `gorm:"index:idx_space_repos_deleted"`
	DeletedAt *time.Time `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SpaceRecord is the current value of a record in a permissioned repo.
// CanonicalCBOR is stored verbatim as the record's canonical DAG-CBOR bytes.
type SpaceRecord struct {
	Space         string `gorm:"primaryKey;index:idx_space_records_space_author"`
	Author        string `gorm:"primaryKey;index:idx_space_records_space_author"`
	Collection    string `gorm:"primaryKey;index:idx_space_records_record"`
	Rkey          string `gorm:"primaryKey;index:idx_space_records_record"`
	CID           string `gorm:"column:cid"`
	CanonicalCBOR []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SpaceRepoOp is one retained operation in a repo's append-only operation log.
// A nil CurrentCID means delete and a nil PreviousCID means create.
type SpaceRepoOp struct {
	Space  string `gorm:"primaryKey;index:idx_space_repo_ops_repo"`
	Author string `gorm:"primaryKey;index:idx_space_repo_ops_repo"`
	Rev    string `gorm:"primaryKey;index:idx_space_repo_ops_repo,sort:asc"`
	Idx    int    `gorm:"primaryKey;index:idx_space_repo_ops_repo,sort:asc"`

	Collection  string
	Rkey        string
	CurrentCID  *string `gorm:"column:current_cid"`
	PreviousCID *string `gorm:"column:previous_cid"`
	CreatedAt   time.Time
}

// SpaceBlobRef links a blob CID to a record identity in a space. Keeping the
// full record identity in the key makes listBlobs authorization-scoped and lets
// callers enumerate all references without a global blob visibility leak.
type SpaceBlobRef struct {
	Space      string `gorm:"primaryKey;index:idx_space_blob_refs_record"`
	Author     string `gorm:"primaryKey;index:idx_space_blob_refs_record"`
	Collection string `gorm:"primaryKey;index:idx_space_blob_refs_record"`
	Rkey       string `gorm:"primaryKey;index:idx_space_blob_refs_record"`
	CID        string `gorm:"column:cid;primaryKey;index:idx_space_blob_refs_cid"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// SimpleSpace stores host-local configuration for a managed space. Policy and
// AppAccess contain the discriminant (for example, "public" or "allowList");
// ManagingApp and AllowedClientIDs hold the data for the variants that need it.
// AllowedClientIDs is canonical JSON so it remains portable across SQLite and
// Postgres without introducing a database-specific array type.
type SimpleSpace struct {
	URI              string `gorm:"primaryKey"`
	OwnerDID         string `gorm:"column:owner_did;index:idx_simple_spaces_owner"`
	Type             string
	SKey             string
	Policy           string
	ManagingApp      *string
	AppAccess        string
	AllowedClientIDs []byte

	Deleted   bool       `gorm:"index:idx_simple_spaces_deleted"`
	DeletedAt *time.Time `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SimpleSpaceMember is host-local membership state used by the member-list
// SimpleSpace policy. A member may belong to many spaces.
type SimpleSpaceMember struct {
	Space string `gorm:"primaryKey;index:idx_simple_space_members_space"`
	DID   string `gorm:"column:did;primaryKey;index:idx_simple_space_members_did"`

	CreatedAt time.Time
	UpdatedAt time.Time
	RemovedAt *time.Time `gorm:"index"`
}

// SpaceWriter is the writer set for a space. It is deliberately separate from
// SpaceRepo so a host can retain writer registration/endpoint state even while
// a repo snapshot is being replaced or marked deleted.
type SpaceWriter struct {
	Space  string `gorm:"primaryKey;index:idx_space_writers_space"`
	Author string `gorm:"primaryKey;index:idx_space_writers_space"`

	Host           string
	Rev            string
	Hash           []byte
	LastNotifiedAt *time.Time `gorm:"index"`
	Status         string     `gorm:"index:idx_space_writers_status"`
	DeletedAt      *time.Time `gorm:"index"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// SpaceNotifyRegistration is a service's write-notification subscription for a
// space. Re-registering the same service updates this row and its expiry.
type SpaceNotifyRegistration struct {
	Space   string `gorm:"primaryKey;index:idx_space_notify_registrations_space"`
	Service string `gorm:"primaryKey;index:idx_space_notify_registrations_space"`

	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SpaceNotifyDelivery is a durable best-effort notification outbox entry.
// Payload may contain the canonical request body; the individual fields make
// retry, inspection, and de-duplication possible without decoding it.
type SpaceNotifyDelivery struct {
	ID             uint   `gorm:"primaryKey"`
	IdempotencyKey string `gorm:"uniqueIndex"`
	Kind           string `gorm:"index:idx_space_notify_deliveries_kind"`

	Space   string `gorm:"index:idx_space_notify_deliveries_space"`
	Service string `gorm:"index:idx_space_notify_deliveries_service"`
	Author  string
	Rev     string
	Hash    []byte
	Deleted bool
	Payload []byte

	Status        string `gorm:"index:idx_space_notify_deliveries_status"`
	AttemptCount  int
	NextAttemptAt *time.Time `gorm:"index"`
	ExpiresAt     time.Time  `gorm:"index"`
	DeliveredAt   *time.Time
	LastError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SpaceTombstone records deletion of a space. The space URI is the primary key
// so deletion notification and replay handling are idempotent.
type SpaceTombstone struct {
	Space              string `gorm:"primaryKey"`
	OwnerDID           string `gorm:"column:owner_did"`
	SourceDID          string `gorm:"column:source_did"`
	SourceNotification string
	DeletedAt          time.Time `gorm:"index"`
	CreatedAt          time.Time
}

// SpaceReplayJTI is a durable single-use-token/DPoP replay record. JTI is
// globally unique because a token replay must be rejected regardless of which
// space or endpoint first consumed it.
type SpaceReplayJTI struct {
	JTI       string    `gorm:"primaryKey"`
	TokenType string    `gorm:"index:idx_space_replay_jtis_type"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

// SpaceReplay is retained as a concise compatibility alias for callers that
// refer to the record by its purpose rather than its storage key.
type SpaceReplay = SpaceReplayJTI

// SpaceModels returns every Spaces persistence model. Keep this list as the
// single source of truth for production and test AutoMigrate calls.
func SpaceModels() []any {
	return []any{
		&SpaceRepo{},
		&SpaceRecord{},
		&SpaceRepoOp{},
		&SpaceBlobRef{},
		&SimpleSpace{},
		&SimpleSpaceMember{},
		&SpaceWriter{},
		&SpaceNotifyRegistration{},
		&SpaceNotifyDelivery{},
		&SpaceTombstone{},
		&SpaceReplayJTI{},
	}
}
