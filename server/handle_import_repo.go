package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atdata"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/sqlite_blockstore"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"github.com/labstack/echo/v4"
)

// importRepoMaxBodyBytes caps the size of an imported repo CAR. Records-only
// CARs are typically tens of MB even for very large accounts, so 100 MB has
// generous headroom while preventing an authenticated user from ballooning
// the process heap with an unbounded read.
const importRepoMaxBodyBytes = 100 << 20

func (s *Server) handleRepoImportRepo(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleImportRepo")

	urepo := e.Get("repo").(*models.RepoActor)

	body := http.MaxBytesReader(e.Response(), e.Request().Body, importRepoMaxBodyBytes)
	b, err := io.ReadAll(body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return e.JSON(http.StatusRequestEntityTooLarge, map[string]string{
				"error":   "RequestEntityTooLarge",
				"message": "imported repo CAR exceeds the 100 MB limit",
			})
		}
		logger.Error("could not read bytes in import request", "error", err)
		return helpers.ServerError(e, nil)
	}

	r, importedBlocks, records, err := readRepoImport(ctx, b, urepo.Repo.Did)
	if err != nil {
		logger.Error("invalid repository import", "error", err)
		return helpers.InputError(e, nil)
	}

	conflict := errors.New("repository changed during import")
	err = s.db.Transaction(ctx, func(tx *db.DB) error {
		bs := sqlite_blockstore.New(urepo.Repo.Did, tx)
		if err := tx.Exec(ctx, "DELETE FROM records WHERE did = ?", nil, urepo.Repo.Did).Error; err != nil {
			return err
		}
		if err := tx.Exec(ctx, "DELETE FROM blocks WHERE did = ?", nil, urepo.Repo.Did).Error; err != nil {
			return err
		}
		for _, block := range importedBlocks {
			if err := bs.Put(ctx, block); err != nil {
				return err
			}
		}
		if len(records) > 0 {
			if err := tx.Client().WithContext(ctx).CreateInBatches(&records, 100).Error; err != nil {
				return err
			}
		}
		// Preserve Cocoon's policy of re-signing with the destination key.
		root, rev, err := commitRepo(ctx, bs, r, urepo.Repo.SigningKey)
		if err != nil {
			return err
		}
		result := tx.Exec(ctx, "UPDATE repos SET root = ?, rev = ? WHERE did = ? AND rev = ?", nil, root.Bytes(), rev, urepo.Repo.Did, urepo.Rev)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return conflict
		}
		return nil
	})
	if errors.Is(err, conflict) {
		return e.JSON(http.StatusConflict, map[string]string{"error": "InvalidSwap", "message": conflict.Error()})
	}
	if err != nil {
		logger.Error("could not commit repository import", "error", err)
		return helpers.ServerError(e, nil)
	}
	return e.NoContent(http.StatusOK)
}

// Validate against the CAR alone, not blocks left over from an earlier repo.
func readRepoImport(ctx context.Context, body []byte, did string) (*atp.Repo, []blocks.Block, []models.Record, error) {
	cs, err := car.NewCarReader(bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(cs.Header.Roots) != 1 {
		return nil, nil, nil, fmt.Errorf("expected one CAR root")
	}
	bs := atp.NewTinyBlockstore()
	var imported []blocks.Block
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		block, err := cs.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		if err := bs.Put(ctx, block); err != nil {
			return nil, nil, nil, err
		}
		imported = append(imported, block)
	}
	root, err := bs.Get(ctx, cs.Header.Roots[0])
	if err != nil {
		return nil, nil, nil, err
	}
	var commit atp.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(root.RawData())); err != nil {
		return nil, nil, nil, err
	}
	if err := commit.VerifyStructure(); err != nil {
		return nil, nil, nil, err
	}
	if commit.DID != did {
		return nil, nil, nil, fmt.Errorf("commit DID does not match account")
	}
	r, err := openRepo(ctx, bs, cs.Header.Roots[0], did)
	if err != nil {
		return nil, nil, nil, err
	}
	if r.MST.IsPartial() {
		return nil, nil, nil, fmt.Errorf("incomplete repository tree")
	}
	if err := r.MST.Verify(); err != nil {
		return nil, nil, nil, err
	}
	var records []models.Record
	clock := syntax.NewTIDClock(0)
	err = r.MST.Walk(func(key []byte, c cid.Cid) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		nsid, rkey, ok := strings.Cut(string(key), "/")
		if !ok {
			return fmt.Errorf("invalid record path")
		}
		if _, err := syntax.ParseNSID(nsid); err != nil {
			return err
		}
		if _, err := syntax.ParseRecordKey(rkey); err != nil {
			return err
		}
		block, err := bs.Get(ctx, c)
		if err != nil {
			return err
		}
		if _, err := atdata.UnmarshalCBOR(block.RawData()); err != nil {
			return err
		}
		records = append(records, models.Record{
			Did: did, CreatedAt: clock.Next().String(), Nsid: nsid, Rkey: rkey,
			Cid: c.String(), Value: block.RawData(),
		})
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return r, imported, records, nil
}
