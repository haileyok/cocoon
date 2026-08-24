package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
)

// s3BlobClient captures the common client operations used by blob storage and
// deletion. AWS clients are safe for concurrent use, so one configured client
// can be reused by request handlers and the deletion worker.
type s3BlobClient interface {
	PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
	GetObject(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	DeleteObject(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
}

func (s *Server) s3Service() (s3BlobClient, error) {
	if s == nil {
		return nil, errors.New("S3 client is unavailable")
	}
	s.s3ClientMu.Lock()
	defer s.s3ClientMu.Unlock()
	if s.s3Client != nil {
		return s.s3Client, nil
	}
	if s.s3Config == nil || s.s3Config.Region == "" || s.s3Config.Bucket == "" {
		return nil, errors.New("S3 client is unavailable")
	}
	config := &aws.Config{
		Region:      aws.String(s.s3Config.Region),
		Credentials: credentials.NewStaticCredentials(s.s3Config.AccessKey, s.s3Config.SecretKey, ""),
	}
	if s.s3Config.Endpoint != "" {
		config.Endpoint = aws.String(s.s3Config.Endpoint)
		config.S3ForcePathStyle = aws.Bool(true)
	}
	sess, err := session.NewSession(config)
	if err != nil {
		return nil, errors.New("S3 client is unavailable")
	}
	s.s3Client = s3.New(sess)
	return s.s3Client, nil
}

func (s *Server) SetBlobDeletionS3Client(client BlobDeletionS3Client) {
	if s == nil {
		return
	}
	s.s3ClientMu.Lock()
	s.blobDeletionClient = client
	s.s3ClientMu.Unlock()
}

func (s *Server) blobDeletionService() (BlobDeletionS3Client, error) {
	if s == nil {
		return nil, errors.New("S3 client is unavailable")
	}
	s.s3ClientMu.Lock()
	client := s.blobDeletionClient
	s.s3ClientMu.Unlock()
	if client != nil {
		return client, nil
	}
	return s.s3Service()
}

func s3BlobObjectKey(did string, rawCID []byte) (string, error) {
	parsed, err := cid.Cast(rawCID)
	if err != nil {
		return "", errors.New("invalid blob CID")
	}
	return fmt.Sprintf("blobs/%s/%s", did, parsed.String()), nil
}

// newS3BlobObjectKey gives each upload an immutable generation identity. The
// CID remains in the path for operational discoverability, but the random
// component prevents a later account incarnation with the same DID/CID from
// reusing an old pending-deletion target.
func newS3BlobObjectKey(did string, rawCID []byte) (string, error) {
	parsed, err := cid.Cast(rawCID)
	if err != nil {
		return "", errors.New("invalid blob CID")
	}
	generation := make([]byte, 16)
	if _, err := rand.Read(generation); err != nil {
		return "", errors.New("could not generate blob object identity")
	}
	return fmt.Sprintf("blobs/%s/%s/%s", did, parsed.String(), hex.EncodeToString(generation)), nil
}

// blobS3Target resolves the persisted target for a blob. Empty ObjectKey is a
// deliberate backwards-compatible marker for rows created before generation
// keys existed; those rows use the original DID/CID key and current bucket.
func blobS3Target(blob models.Blob, config *S3Config) (string, string, error) {
	bucket := strings.TrimSpace(blob.Bucket)
	if bucket == "" && config != nil {
		bucket = strings.TrimSpace(config.Bucket)
	}
	if bucket == "" {
		return "", "", errors.New("S3 blob has no bucket")
	}
	objectKey := strings.TrimSpace(blob.ObjectKey)
	if objectKey == "" {
		var err error
		objectKey, err = s3BlobObjectKey(blob.Did, blob.Cid)
		if err != nil {
			return "", "", err
		}
	}
	if objectKey == "" {
		return "", "", errors.New("S3 blob has no object key")
	}
	return bucket, objectKey, nil
}

func blobDeletionIdempotencyKey(bucket, objectKey string) string {
	// New generation keys are globally unique, so preserve their historical
	// key-only idempotency value. Legacy blobs use blobs/{did}/{cid}; include the
	// snapshotted bucket for those rows so two legacy buckets cannot collide.
	if strings.Count(objectKey, "/") == 2 {
		return bucket + "\x00" + objectKey
	}
	return objectKey
}
