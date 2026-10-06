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

	// simplespace host
	s.echo.POST("/xrpc/com.atproto.simplespace.createSpace", s.handleSimplespaceCreateSpace, session...)
	s.echo.POST("/xrpc/com.atproto.simplespace.putMember", s.handleSimplespacePutMember, session...)
	s.echo.POST("/xrpc/com.atproto.simplespace.removeMember", s.handleSimplespaceRemoveMember, session...)
	s.echo.POST("/xrpc/com.atproto.simplespace.updateSpace", s.handleSimplespaceUpdateSpace, session...)
	s.echo.POST("/xrpc/com.atproto.simplespace.deleteSpace", s.handleSimplespaceDeleteSpace, session...)
	s.echo.GET("/xrpc/com.atproto.simplespace.listMembers", s.handleSimplespaceListMembers, session...)
	s.echo.GET("/xrpc/com.atproto.simplespace.getSpace", s.handleSimplespaceGetSpace, s.spaceReadMiddleware)

	// credentials
	s.echo.GET("/xrpc/com.atproto.space.getDelegationToken", s.handleSpaceGetDelegationToken, session...)
	// authenticated by the delegation token and request signature in the handler
	s.echo.POST("/xrpc/com.atproto.space.getSpaceCredential", s.handleSpaceGetSpaceCredential)
	// service auth from the space authority, verified in the handler
	s.echo.POST("/xrpc/com.atproto.space.notifyCredentialRevoked", s.handleSpaceNotifyCredentialRevoked)

	// sync: write notifications, registrations and full-state recovery
	s.echo.POST("/xrpc/com.atproto.space.notifyWrite", s.handleSpaceNotifyWrite)
	s.echo.POST("/xrpc/com.atproto.space.registerNotify", s.handleSpaceRegisterNotify)
	s.echo.POST("/xrpc/com.atproto.space.unregisterNotify", s.handleSpaceUnregisterNotify)
	s.echo.GET("/xrpc/com.atproto.space.listRepos", s.handleSpaceListRepos)
	s.echo.GET("/xrpc/com.atproto.space.getRepo", s.handleSpaceGetRepo, s.spaceReadMiddleware)
}
