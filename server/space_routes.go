package server

import "github.com/labstack/echo/v4"

// addSpaceRoutes registers the Spaces (permissioned data) methods.
func (s *Server) addSpaceRoutes() {
	session := []echo.MiddlewareFunc{s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware}

	// record writes: the caller's own repo
	s.echo.POST("/xrpc/com.atproto.space.createRecord", s.handleSpaceCreateRecord, session...)
	s.echo.POST("/xrpc/com.atproto.space.putRecord", s.handleSpacePutRecord, session...)
	s.echo.POST("/xrpc/com.atproto.space.deleteRecord", s.handleSpaceDeleteRecord, session...)
	s.echo.POST("/xrpc/com.atproto.space.applyWrites", s.handleSpaceApplyWrites, session...)
	s.echo.GET("/xrpc/com.atproto.space.listSpaces", s.handleSpaceListSpaces, session...)

	// reads: an account's own repo, or any repo with a space credential
	s.echo.GET("/xrpc/com.atproto.space.getRecord", s.handleSpaceGetRecord, s.spaceReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.space.listRecords", s.handleSpaceListRecords, s.spaceReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.space.listRepoOps", s.handleSpaceListRepoOps, s.spaceReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.space.getLatestCommit", s.handleSpaceGetLatestCommit, s.spaceReadMiddleware)

	// space lifecycle and policy: the spaces an account governs
	s.echo.POST("/xrpc/com.atproto.space.createSpace", s.handleSpaceCreateSpace, session...)
	s.echo.POST("/xrpc/com.atproto.space.updateSpace", s.handleSpaceUpdateSpace, session...)
	s.echo.POST("/xrpc/com.atproto.space.deleteSpace", s.handleSpaceDeleteSpace, session...)
	s.echo.POST("/xrpc/com.atproto.space.removeWriter", s.handleSpaceRemoveWriter, session...)
	s.echo.GET("/xrpc/com.atproto.space.getSpace", s.handleSpaceGetSpace, session...)
	s.echo.POST("/xrpc/com.atproto.space.clearRecords", s.handleSpaceClearRecords, session...)
	s.echo.POST("/xrpc/com.atproto.memberspace.putMembers", s.handleMemberspacePutMembers, session...)
	s.echo.POST("/xrpc/com.atproto.memberspace.removeMembers", s.handleMemberspaceRemoveMembers, session...)
	s.echo.GET("/xrpc/com.atproto.memberspace.listMembers", s.handleMemberspaceListMembers, session...)

	// account migration: the host-side state of a space and an account's repo
	s.echo.GET("/xrpc/com.atproto.space.exportSpaceMeta", s.handleSpaceExportSpaceMeta, session...)
	s.echo.POST("/xrpc/com.atproto.space.importSpaceMeta", s.handleSpaceImportSpaceMeta, session...)
	s.echo.POST("/xrpc/com.atproto.space.importRepo", s.handleSpaceImportRepo, session...)

	// credentials
	s.echo.GET("/xrpc/com.atproto.space.getDelegationToken", s.handleSpaceGetDelegationToken, session...)
	// unauthenticated: a delegation token and client attestation, when the
	// space requires them, arrive in the request body
	s.echo.POST("/xrpc/com.atproto.space.authorizeSpaceSync", s.handleSpaceAuthorizeSpaceSync)
	// service auth from the space authority, verified in the handler
	s.echo.POST("/xrpc/com.atproto.space.notifyCredentialsRevoked", s.handleSpaceNotifyCredentialsRevoked)

	// sync: repo update notifications, the writer set and full-state recovery
	s.echo.POST("/xrpc/com.atproto.space.notifyRepoUpdate", s.handleSpaceNotifyRepoUpdate)
	s.echo.GET("/xrpc/com.atproto.space.listWriters", s.handleSpaceListWriters)
	s.echo.GET("/xrpc/com.atproto.space.getRepo", s.handleSpaceGetRepo, s.spaceReadMiddleware)

	// blobs
	s.echo.GET("/xrpc/com.atproto.space.getBlob", s.handleSpaceGetBlob, s.spaceReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.space.listBlobs", s.handleSpaceListBlobs, s.spaceReadMiddleware)
}
