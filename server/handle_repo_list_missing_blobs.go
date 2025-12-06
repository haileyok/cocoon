package server

import (
	"fmt"
	"strconv"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoListMissingBlobsResponse struct {
	Cursor *string                                    `json:"cursor,omitempty"`
	Blobs  []ComAtprotoRepoListMissingBlobsRecordBlob `json:"blobs"`
}

type ComAtprotoRepoListMissingBlobsRecordBlob struct {
	Cid       string `json:"cid"`
	RecordUri string `json:"recordUri"`
}

func (s *Server) handleListMissingBlobs(e echo.Context) error {
	urepo := e.Get("repo").(*models.RepoActor)

	limitStr := e.QueryParam("limit")
	cursor := e.QueryParam("cursor")

	limit := 500
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	var records []models.Record
	if err := s.db.Raw("SELECT * FROM records WHERE did = ?", nil, urepo.Repo.Did).Scan(&records).Error; err != nil {
		s.logger.Error("failed to get records for listMissingBlobs", "error", err)
		return helpers.ServerError(e, nil)
	}

	type blobRef struct {
		cid       cid.Cid
		recordUri string
	}
	var allBlobRefs []blobRef

	for _, rec := range records {
		cids, err := getBlobCidsFromRecord(rec.Value)
		if err != nil {
			continue
		}
		recordUri := fmt.Sprintf("at://%s/%s/%s", urepo.Repo.Did, rec.Nsid, rec.Rkey)
		for _, c := range cids {
			allBlobRefs = append(allBlobRefs, blobRef{cid: c, recordUri: recordUri})
		}
	}

	var missingBlobs []ComAtprotoRepoListMissingBlobsRecordBlob
	seenCids := make(map[string]bool)

	for _, ref := range allBlobRefs {
		cidStr := ref.cid.String()

		if seenCids[cidStr] {
			continue
		}

		if cursor != "" && cidStr <= cursor {
			continue
		}

		var count int64
		if err := s.db.Raw("SELECT COUNT(*) FROM blobs WHERE did = ? AND cid = ?", nil, urepo.Repo.Did, ref.cid.Bytes()).Scan(&count).Error; err != nil {
			continue
		}

		if count == 0 {
			missingBlobs = append(missingBlobs, ComAtprotoRepoListMissingBlobsRecordBlob{
				Cid:       cidStr,
				RecordUri: ref.recordUri,
			})
			seenCids[cidStr] = true

			if len(missingBlobs) >= limit {
				break
			}
		}
	}

	var nextCursor *string
	if len(missingBlobs) > 0 && len(missingBlobs) >= limit {
		lastCid := missingBlobs[len(missingBlobs)-1].Cid
		nextCursor = &lastCid
	}

	return e.JSON(200, ComAtprotoRepoListMissingBlobsResponse{
		Cursor: nextCursor,
		Blobs:  missingBlobs,
	})
}

func getBlobCidsFromRecord(cbor []byte) ([]cid.Cid, error) {
	var cids []cid.Cid

	decoded, err := atdata.UnmarshalCBOR(cbor)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling cbor: %w", err)
	}

	var deepiter func(any) error
	deepiter = func(item any) error {
		switch val := item.(type) {
		case map[string]any:
			if val["$type"] == "blob" {
				if ref, ok := val["ref"].(cid.Cid); ok {
					cids = append(cids, ref)
				} else if refStr, ok := val["ref"].(string); ok {
					c, err := cid.Parse(refStr)
					if err == nil {
						cids = append(cids, c)
					}
				}
			}
			for _, v := range val {
				if err := deepiter(v); err != nil {
					return err
				}
			}
		case []any:
			for _, v := range val {
				if err := deepiter(v); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := deepiter(decoded); err != nil {
		return nil, err
	}

	return cids, nil
}
