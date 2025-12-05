package server

import (
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoListMissingBlobsResponse struct {
	Cursor *string                                    `json:"cursor,omitempty"`
	Blobs  []ComAtprotoRepoListMissingBlobsRecordBlob `json:"blobs"`
}

type ComAtprotoRepoListMissingBlobsRecordBlob struct {
	Cid        string `json:"cid"`
	RecordUri  string `json:"recordUri"`
}

func (s *Server) handleListMissingBlobs(e echo.Context) error {
	return e.JSON(200, ComAtprotoRepoListMissingBlobsResponse{
		Blobs: []ComAtprotoRepoListMissingBlobsRecordBlob{},
	})
}
