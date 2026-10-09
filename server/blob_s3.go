package server

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/ipfs/go-cid"
)

// s3Client builds an S3 client from the server's S3 config.
func (s *Server) s3Client() (*s3.S3, error) {
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
		return nil, err
	}
	return s3.New(sess), nil
}

func s3BlobKey(did string, c cid.Cid) string {
	return fmt.Sprintf("blobs/%s/%s", did, c.String())
}

func isS3NoSuchKey(err error) bool {
	var aerr awserr.Error
	return errors.As(err, &aerr) && aerr.Code() == s3.ErrCodeNoSuchKey
}

// getS3Blob opens a blob stored in S3. Blobs are normally stored at
// blobs/{did}/{cid}, but some were stored as a file inside a directory named
// by the cid (blobs/{did}/{cid}/{name}), so if the flat key doesn't exist we
// fall back to the first object under that prefix. The caller must close the
// returned body. A missing blob yields a NoSuchKey error (see isS3NoSuchKey).
func (s *Server) getS3Blob(ctx context.Context, did string, c cid.Cid) (io.ReadCloser, error) {
	svc, err := s.s3Client()
	if err != nil {
		return nil, err
	}

	key := s3BlobKey(did, c)
	out, err := svc.GetObjectWithContext(ctx, &s3.GetObjectInput{Bucket: aws.String(s.s3Config.Bucket), Key: aws.String(key)})
	if err == nil {
		return out.Body, nil
	}
	if !isS3NoSuchKey(err) {
		return nil, err
	}

	list, lerr := svc.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.s3Config.Bucket),
		Prefix:  aws.String(key + "/"),
		MaxKeys: aws.Int64(1),
	})
	if lerr != nil || len(list.Contents) == 0 || list.Contents[0].Key == nil {
		// report the original miss, not the listing outcome
		return nil, err
	}

	out, err = svc.GetObjectWithContext(ctx, &s3.GetObjectInput{Bucket: aws.String(s.s3Config.Bucket), Key: list.Contents[0].Key})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}
