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
}
