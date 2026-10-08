package models

// Spaces (permissioned data). The reference PDS keeps these tables in each
// account's own store; here they share one database, so every row carries the
// DID of the account it belongs to (Did).

// Space is a space this account holds a repo in, or governs. DeletedAt marks
// a deleted space whose row survives as a tombstone.
type Space struct {
	Did       string `gorm:"primaryKey"`
	Uri       string `gorm:"primaryKey"`
	Authority string `gorm:"not null;index"`
	Type      string `gorm:"not null"`
	CreatedAt string `gorm:"not null"`
	DeletedAt *string
}

// SimplespaceConfig is the governance config of a space this account is the
// authority for.
type SimplespaceConfig struct {
	Did              string `gorm:"primaryKey"`
	Uri              string `gorm:"primaryKey"`
	ReadPolicy       string `gorm:"not null"`
	ReadManagingApp  *string
	WritePolicy      string `gorm:"not null"`
	WriteManagingApp *string
	AppAccessType    string `gorm:"not null"`
	AppAllowed       string `gorm:"not null"` // JSON array of client IDs
}

// SimplespaceMember is a member of a governed space.
type SimplespaceMember struct {
	Did       string `gorm:"primaryKey"`
	Space     string `gorm:"primaryKey"`
	MemberDid string `gorm:"primaryKey"`
	Read      bool   `gorm:"not null"`
	Write     bool   `gorm:"not null"`
}

// SpaceRecord is a record in this account's repo for a space. Uri is globally
// unique since it names the author.
type SpaceRecord struct {
	Uri        string `gorm:"primaryKey"`
	Did        string `gorm:"not null;uniqueIndex:idx_space_record_path,priority:1;index:idx_space_record_rev,priority:1"`
	Space      string `gorm:"not null;uniqueIndex:idx_space_record_path,priority:2;index:idx_space_record_rev,priority:2"`
	Collection string `gorm:"not null;uniqueIndex:idx_space_record_path,priority:3"`
	Rkey       string `gorm:"not null;uniqueIndex:idx_space_record_path,priority:4"`
	Cid        string `gorm:"not null"`
	Value      []byte `gorm:"not null"`
	RepoRev    string `gorm:"not null;index:idx_space_record_rev,priority:3"`
	IndexedAt  string `gorm:"not null"`
}

// SpaceRecordBlob ties a blob to a space record that references it.
type SpaceRecordBlob struct {
	Did       string `gorm:"not null;index"`
	BlobCid   string `gorm:"primaryKey"`
	RecordUri string `gorm:"primaryKey;index"`
}

// SpaceRepo is this account's repo state in a space: the set hash state and
// the latest rev. Both are nil until the first write.
type SpaceRepo struct {
	Did     string `gorm:"primaryKey"`
	Space   string `gorm:"primaryKey"`
	SetHash []byte
	Rev     *string
}

// SpaceRecordOplog is one op of a space repo commit.
type SpaceRecordOplog struct {
	Did        string `gorm:"primaryKey"`
	Space      string `gorm:"primaryKey"`
	Rev        string `gorm:"primaryKey"`
	Idx        int    `gorm:"primaryKey;autoIncrement:false"`
	Action     string `gorm:"not null"`
	Uri        string `gorm:"not null"`
	Collection string `gorm:"not null"`
	Rkey       string `gorm:"not null"`
	Cid        *string
	Prev       *string
}

// SpaceWriter is, on the authority, the latest known state of a writer's repo
// in a governed space, sequenced by SpaceRev.
type SpaceWriter struct {
	Did       string `gorm:"primaryKey"`
	Space     string `gorm:"primaryKey;index:idx_space_writer_space_rev,priority:1"`
	WriterDid string `gorm:"primaryKey"`
	RepoRev   string `gorm:"not null"`
	SpaceRev  string `gorm:"not null;index:idx_space_writer_space_rev,priority:2"`
	Hash      []byte `gorm:"not null"`
}

// SpaceCredentialRecipient is a service registered (registerNotify) to receive
// a governed space's write notifications.
type SpaceCredentialRecipient struct {
	Did             string `gorm:"primaryKey"`
	Space           string `gorm:"primaryKey"`
	ServiceDid      string `gorm:"primaryKey"`
	ServiceEndpoint string `gorm:"not null"`
	ExpiresAt       string `gorm:"not null"`
}

// SpaceNotificationRetry is a writer's notifyWrite that failed and waits to be
// resent to the authority, one per repo and space.
type SpaceNotificationRetry struct {
	Repo      string `gorm:"primaryKey"`
	Space     string `gorm:"primaryKey"`
	RepoRev   string `gorm:"not null"`
	Hash      []byte `gorm:"not null"`
	Attempts  int    `gorm:"not null"`
	RetryAt   int64  `gorm:"not null;index"`
	ExpiresAt int64  `gorm:"not null"`
}

// RevokedSpaceCredential is a space credential revoked by its authority, kept
// until it would have expired.
type RevokedSpaceCredential struct {
	Space     string `gorm:"primaryKey"`
	Jti       string `gorm:"primaryKey"`
	ExpiresAt string `gorm:"not null;index"`
}

// SpaceUsedJti records a single-use token (delegation token, client
// attestation) until it expires, so it can't be replayed.
type SpaceUsedJti struct {
	Namespace string `gorm:"primaryKey"`
	Jti       string `gorm:"primaryKey"`
	ExpiresAt int64  `gorm:"not null;index"`
}

// SpaceModels lists the space tables for migration.
func SpaceModels() []any {
	return []any{
		&Space{}, &SimplespaceConfig{}, &SimplespaceMember{}, &SpaceRecord{},
		&SpaceRecordBlob{}, &SpaceRepo{}, &SpaceRecordOplog{}, &SpaceWriter{},
		&SpaceCredentialRecipient{}, &SpaceNotificationRetry{},
		&RevokedSpaceCredential{}, &SpaceUsedJti{},
	}
}
