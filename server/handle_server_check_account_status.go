package server

import (
	"context"
	"slices"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerCheckAccountStatusResponse struct {
	Activated          bool   `json:"activated"`
	ValidDid           bool   `json:"validDid"`
	RepoCommit         string `json:"repoCommit"`
	RepoRev            string `json:"repoRev"`
	RepoBlocks         int64  `json:"repoBlocks"`
	IndexedRecords     int64  `json:"indexedRecords"`
	PrivateStateValues int64  `json:"privateStateValues"`
	ExpectedBlobs      int64  `json:"expectedBlobs"`
	ImportedBlobs      int64  `json:"importedBlobs"`
}

func (s *Server) handleServerCheckAccountStatus(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerCheckAccountStatus")

	urepo := e.Get("repo").(*models.RepoActor)

	resp := ComAtprotoServerCheckAccountStatusResponse{
		Activated: urepo.Repo.Active(),
		ValidDid:  s.validAccountDID(ctx, urepo),
		RepoRev:   urepo.Rev,
	}

	rootcid, err := cid.Cast(urepo.Root)
	if err != nil {
		logger.Error("error casting cid", "error", err)
		return helpers.ServerError(e, nil)
	}
	resp.RepoCommit = rootcid.String()

	type CountResp struct {
		Ct int64
	}

	var blockCtResp CountResp
	if err := s.db.Raw(ctx, "SELECT COUNT(*) AS ct FROM blocks WHERE did = ?", nil, urepo.Repo.Did).Scan(&blockCtResp).Error; err != nil {
		logger.Error("error getting block count", "error", err)
		return helpers.ServerError(e, nil)
	}
	resp.RepoBlocks = blockCtResp.Ct

	var records []models.Record
	if err := s.db.Raw(ctx, "SELECT value FROM records WHERE did = ?", nil, urepo.Repo.Did).Scan(&records).Error; err != nil {
		logger.Error("error getting records", "error", err)
		return helpers.ServerError(e, nil)
	}
	refs, err := countBlobRefs(records)
	if err != nil {
		logger.Error("error counting blob references", "error", err)
		return helpers.ServerError(e, nil)
	}
	resp.IndexedRecords = int64(len(records))
	resp.ExpectedBlobs = int64(len(refs))

	var blobCtResp CountResp
	// Uploads publish their CID only once complete; retries may create duplicate rows.
	if err := s.db.Raw(ctx, "SELECT COUNT(DISTINCT cid) AS ct FROM blobs WHERE did = ? AND LENGTH(cid) > 0", nil, urepo.Repo.Did).Scan(&blobCtResp).Error; err != nil {
		logger.Error("error getting blob count", "error", err)
		return helpers.ServerError(e, nil)
	}
	resp.ImportedBlobs = blobCtResp.Ct

	return e.JSON(200, resp)
}

func (s *Server) validAccountDID(ctx context.Context, repo *models.RepoActor) bool {
	key, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		return false
	}
	creds, err := s.plcClient.CreateDidCredentials(key, "", repo.Handle)
	if err != nil {
		return false
	}
	did := repo.Repo.Did
	if strings.HasPrefix(did, "did:plc:") {
		data, err := s.plcClient.GetData(ctx, did)
		return err == nil && data.Did == did &&
			data.Services["atproto_pds"] == creds.Services["atproto_pds"] &&
			data.VerificationMethods["atproto"] == creds.VerificationMethods["atproto"] &&
			slices.Contains(data.RotationKeys, creds.RotationKeys[0])
	}
	if !strings.HasPrefix(did, "did:web:") {
		return false
	}
	// Migration checks must not use the pre-cutover document from cache.
	doc, err := s.passport.FetchDoc(context.WithValue(ctx, "skip-cache", true), did)
	if err != nil || doc.Id != did {
		return false
	}
	var endpoint, signingKey string
	for _, service := range doc.Service {
		if (service.Id == "#atproto_pds" || service.Id == did+"#atproto_pds") && service.Type == "AtprotoPersonalDataServer" {
			endpoint = service.ServiceEndpoint
			break
		}
	}
	for _, method := range doc.VerificationMethods {
		if method.Id == "#atproto" || method.Id == did+"#atproto" {
			signingKey = "did:key:" + method.PublicKeyMultibase
			break
		}
	}
	return endpoint == creds.Services["atproto_pds"].Endpoint && signingKey == creds.VerificationMethods["atproto"]
}
