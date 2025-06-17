package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/domodwyer/mailyak/v3"
	"github.com/go-playground/validator"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	slogecho "github.com/samber/slog-echo"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type S3Config struct {
	BackupsEnabled bool
	Endpoint       string
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
}

type Server struct {
	http       *http.Client
	httpd      *http.Server
	mail       *mailyak.MailYak
	mailLk     *sync.Mutex
	echo       *echo.Echo
	db         *db.DB
	plcClient  *plc.Client
	logger     *slog.Logger
	config     *config
	privateKey *ecdsa.PrivateKey
	repoman    *RepoMan
	evtman     *events.EventManager
	passport   *identity.Passport

	dbName   string
	s3Config *S3Config

	oauthClientMan *OauthClientManager
	oauthDpopMan   *OauthDpopManager
}

type Args struct {
	Addr            string
	DbName          string
	Logger          *slog.Logger
	Version         string
	Did             string
	Hostname        string
	RotationKeyPath string
	JwkPath         string
	ContactEmail    string
	Relays          []string
	AdminPassword   string

	SmtpUser  string
	SmtpPass  string
	SmtpHost  string
	SmtpPort  string
	SmtpEmail string
	SmtpName  string

	StaticFilePath string

	S3Config *S3Config
}

type config struct {
	Version        string
	Did            string
	Hostname       string
	ContactEmail   string
	EnforcePeering bool
	Relays         []string
	AdminPassword  string
	SmtpEmail      string
	SmtpName       string
	StaticFilePath string
}

type CustomValidator struct {
	validator *validator.Validate
}

type ValidationError struct {
	error
	Field string
	Tag   string
}

func (cv *CustomValidator) Validate(i any) error {
	if err := cv.validator.Struct(i); err != nil {
		var validateErrors validator.ValidationErrors
		if errors.As(err, &validateErrors) && len(validateErrors) > 0 {
			first := validateErrors[0]
			return ValidationError{
				error: err,
				Field: first.Field(),
				Tag:   first.Tag(),
			}
		}

		return err
	}

	return nil
}

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

func (s *Server) handleAdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		username, password, ok := e.Request().BasicAuth()
		if !ok || username != "admin" || password != s.config.AdminPassword {
			return helpers.InputError(e, to.StringPtr("Unauthorized"))
		}

		if err := next(e); err != nil {
			e.Error(err)
		}

		return nil
	}
}

func (s *Server) handleLegacySessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		authheader := e.Request().Header.Get("authorization")
		if authheader == "" {
			return e.JSON(401, map[string]string{"error": "Unauthorized"})
		}

		pts := strings.Split(authheader, " ")
		if len(pts) != 2 {
			return helpers.ServerError(e, nil)
		}

		if pts[0] == "DPoP" {
			return next(e)
		}

		tokenstr := pts[1]

		token, err := new(jwt.Parser).Parse(tokenstr, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unsupported signing method: %v", t.Header["alg"])
			}

			return s.privateKey.Public(), nil
		})
		if err != nil {
			s.logger.Error("error parsing jwt", "error", err)
			// NOTE: https://github.com/bluesky-social/atproto/discussions/3319
			return e.JSON(400, map[string]string{"error": "ExpiredToken", "message": "token has expired"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			return helpers.InputError(e, to.StringPtr("InvalidToken"))
		}

		isRefresh := e.Request().URL.Path == "/xrpc/com.atproto.server.refreshSession"
		scope := claims["scope"].(string)

		if isRefresh && scope != "com.atproto.refresh" {
			return helpers.InputError(e, to.StringPtr("InvalidToken"))
		} else if !isRefresh && scope != "com.atproto.access" {
			return helpers.InputError(e, to.StringPtr("InvalidToken"))
		}

		table := "tokens"
		if isRefresh {
			table = "refresh_tokens"
		}

		type Result struct {
			Found bool
		}
		var result Result
		if err := s.db.Raw("SELECT EXISTS(SELECT 1 FROM "+table+" WHERE token = ?) AS found", nil, tokenstr).Scan(&result).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return helpers.InputError(e, to.StringPtr("InvalidToken"))
			}

			s.logger.Error("error getting token from db", "error", err)
			return helpers.ServerError(e, nil)
		}

		if !result.Found {
			return helpers.InputError(e, to.StringPtr("InvalidToken"))
		}

		exp, ok := claims["exp"].(float64)
		if !ok {
			s.logger.Error("error getting iat from token")
			return helpers.ServerError(e, nil)
		}

		if exp < float64(time.Now().UTC().Unix()) {
			return helpers.InputError(e, to.StringPtr("ExpiredToken"))
		}

		repo, err := s.getRepoActorByDid(claims["sub"].(string))
		if err != nil {
			s.logger.Error("error fetching repo", "error", err)
			return helpers.ServerError(e, nil)
		}

		e.Set("repo", repo)
		e.Set("did", claims["sub"])
		e.Set("token", tokenstr)

		if err := next(e); err != nil {
			e.Error(err)
		}

		return nil
	}
}

func (s *Server) handleOauthSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		authheader := e.Request().Header.Get("authorization")
		if authheader == "" {
			return e.JSON(401, map[string]string{"error": "Unauthorized"})
		}

		pts := strings.Split(authheader, " ")
		if len(pts) != 2 {
			return helpers.ServerError(e, nil)
		}

		if pts[0] != "DPoP" {
			return next(e)
		}

		accessToken := pts[1]

		proof, err := s.oauthDpopMan.CheckProof(e.Request().Method, "https://"+s.config.Hostname+e.Request().URL.String(), e.Request().Header, to.StringPtr(accessToken))
		if err != nil {
			s.logger.Error("invalid dpop proof", "error", err)
			return helpers.InputError(e, to.StringPtr(err.Error()))
		}

		var oauthToken models.OauthToken
		if err := s.db.Raw("SELECT * FROM oauth_tokens WHERE token = ?", nil, accessToken).Scan(&oauthToken).Error; err != nil {
			s.logger.Error("error finding access token in db", "error", err)
			return helpers.InputError(e, nil)
		}

		if oauthToken.Token == "" {
			return helpers.InputError(e, to.StringPtr("InvalidToken"))
		}

		if *oauthToken.Parameters.DpopJkt != proof.JKT {
			s.logger.Error("jkt mismatch", "token", oauthToken.Parameters.DpopJkt, "proof", proof.JKT)
			return helpers.InputError(e, to.StringPtr("dpop jkt mismatch"))
		}

		if time.Now().After(oauthToken.ExpiresAt) {
			return e.JSON(400, map[string]string{"error": "ExpiredToken", "message": "token has expired"})
		}

		repo, err := s.getRepoActorByDid(oauthToken.Sub)
		if err != nil {
			s.logger.Error("could not find actor in db", "error", err)
			return helpers.ServerError(e, nil)
		}

		e.Set("repo", repo)
		e.Set("did", repo.Repo.Did)
		e.Set("token", accessToken)
		e.Set("scopes", strings.Split(oauthToken.Parameters.Scope, " "))

		return next(e)
	}
}

func New(args *Args) (*Server, error) {
	if args.Addr == "" {
		return nil, fmt.Errorf("addr must be set")
	}

	if args.DbName == "" {
		return nil, fmt.Errorf("db name must be set")
	}

	if args.Did == "" {
		return nil, fmt.Errorf("cocoon did must be set")
	}

	if args.ContactEmail == "" {
		return nil, fmt.Errorf("cocoon contact email is required")
	}

	if _, err := syntax.ParseDID(args.Did); err != nil {
		return nil, fmt.Errorf("error parsing cocoon did: %w", err)
	}

	if args.Hostname == "" {
		return nil, fmt.Errorf("cocoon hostname must be set")
	}

	if args.AdminPassword == "" {
		return nil, fmt.Errorf("admin password must be set")
	}

	if args.Logger == nil {
		args.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	}

	e := echo.New()

	e.Pre(middleware.RemoveTrailingSlash())
	e.Pre(slogecho.New(args.Logger))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowHeaders:     []string{"*"},
		AllowMethods:     []string{"*"},
		AllowCredentials: true,
		MaxAge:           100_000_000,
	}))

	vdtor := validator.New()
	vdtor.RegisterValidation("atproto-handle", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseHandle(fl.Field().String()); err != nil {
			return false
		}
		return true
	})
	vdtor.RegisterValidation("atproto-did", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseDID(fl.Field().String()); err != nil {
			return false
		}
		return true
	})
	vdtor.RegisterValidation("atproto-rkey", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseRecordKey(fl.Field().String()); err != nil {
			return false
		}
		return true
	})
	vdtor.RegisterValidation("atproto-nsid", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseNSID(fl.Field().String()); err != nil {
			return false
		}
		return true
	})

	e.Validator = &CustomValidator{validator: vdtor}

	httpd := &http.Server{
		Addr:    args.Addr,
		Handler: e,
		// shitty defaults but okay for now, needed for import repo
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  5 * time.Minute,
	}

	gdb, err := gorm.Open(sqlite.Open("cocoon.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	dbw := db.NewDB(gdb)

	rkbytes, err := os.ReadFile(args.RotationKeyPath)
	if err != nil {
		return nil, err
	}

	h := util.RobustHTTPClient()

	plcClient, err := plc.NewClient(&plc.ClientArgs{
		H:           h,
		Service:     "https://plc.directory",
		PdsHostname: args.Hostname,
		RotationKey: rkbytes,
	})
	if err != nil {
		return nil, err
	}

	jwkbytes, err := os.ReadFile(args.JwkPath)
	if err != nil {
		return nil, err
	}

	key, err := helpers.ParseJWKFromBytes(jwkbytes)
	if err != nil {
		return nil, err
	}

	var pkey ecdsa.PrivateKey
	if err := key.Raw(&pkey); err != nil {
		return nil, err
	}

	s := &Server{
		http:       h,
		httpd:      httpd,
		echo:       e,
		logger:     args.Logger,
		db:         dbw,
		plcClient:  plcClient,
		privateKey: &pkey,
		config: &config{
			Version:        args.Version,
			Did:            args.Did,
			Hostname:       args.Hostname,
			ContactEmail:   args.ContactEmail,
			EnforcePeering: false,
			Relays:         args.Relays,
			AdminPassword:  args.AdminPassword,
			SmtpName:       args.SmtpName,
			SmtpEmail:      args.SmtpEmail,
			StaticFilePath: args.StaticFilePath,
		},
		evtman:   events.NewEventManager(events.NewMemPersister()),
		passport: identity.NewPassport(h, identity.NewMemCache(10_000)),

		dbName:   args.DbName,
		s3Config: args.S3Config,

		oauthClientMan: NewOauthClientManager(),
		oauthDpopMan:   NewOauthDpopManager(),
	}

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(s.getFilePath("*.html"))),
	}
	e.Renderer = renderer

	s.repoman = NewRepoMan(s) // TODO: this is way too lazy, stop it

	// TODO: should validate these args
	if args.SmtpUser == "" || args.SmtpPass == "" || args.SmtpHost == "" || args.SmtpPort == "" || args.SmtpEmail == "" || args.SmtpName == "" {
		args.Logger.Warn("not enough smpt args were provided. mailing will not work for your server.")
	} else {
		mail := mailyak.New(args.SmtpHost+":"+args.SmtpPort, smtp.PlainAuth("", args.SmtpUser, args.SmtpPass, args.SmtpHost))
		mail.From(s.config.SmtpEmail)
		mail.FromName(s.config.SmtpName)

		s.mail = mail
		s.mailLk = &sync.Mutex{}
	}

	return s, nil
}

func (s *Server) addRoutes() {
	// random stuff
	s.echo.GET("/", s.handleRoot)
	s.echo.GET("/xrpc/_health", s.handleHealth)
	s.echo.GET("/.well-known/did.json", s.handleWellKnown)
	s.echo.GET("/.well-known/oauth-protected-resource", s.handleOauthProtectedResource)
	s.echo.GET("/.well-known/oauth-authorization-server", s.handleOauthAuthorizationServer)
	s.echo.GET("/robots.txt", s.handleRobots)

	// public
	s.echo.GET("/xrpc/com.atproto.identity.resolveHandle", s.handleResolveHandle)
	s.echo.POST("/xrpc/com.atproto.server.createAccount", s.handleCreateAccount)
	s.echo.POST("/xrpc/com.atproto.server.createAccount", s.handleCreateAccount)
	s.echo.POST("/xrpc/com.atproto.server.createSession", s.handleCreateSession)
	s.echo.GET("/xrpc/com.atproto.server.describeServer", s.handleDescribeServer)

	s.echo.GET("/xrpc/com.atproto.repo.describeRepo", s.handleDescribeRepo)
	s.echo.GET("/xrpc/com.atproto.sync.listRepos", s.handleListRepos)
	s.echo.GET("/xrpc/com.atproto.repo.listRecords", s.handleListRecords)
	s.echo.GET("/xrpc/com.atproto.repo.getRecord", s.handleRepoGetRecord)
	s.echo.GET("/xrpc/com.atproto.sync.getRecord", s.handleSyncGetRecord)
	s.echo.GET("/xrpc/com.atproto.sync.getBlocks", s.handleGetBlocks)
	s.echo.GET("/xrpc/com.atproto.sync.getLatestCommit", s.handleSyncGetLatestCommit)
	s.echo.GET("/xrpc/com.atproto.sync.getRepoStatus", s.handleSyncGetRepoStatus)
	s.echo.GET("/xrpc/com.atproto.sync.getRepo", s.handleSyncGetRepo)
	s.echo.GET("/xrpc/com.atproto.sync.subscribeRepos", s.handleSyncSubscribeRepos)
	s.echo.GET("/xrpc/com.atproto.sync.listBlobs", s.handleSyncListBlobs)
	s.echo.GET("/xrpc/com.atproto.sync.getBlob", s.handleSyncGetBlob)

	// oauth basic
	s.echo.GET("/oauth/jwks", s.handleOauthJwks)
	s.echo.GET("/oauth/authorize", s.handleOauthAuthorizeGet)
	s.echo.POST("/oauth/authorize", s.handleOauthAuthorizePost)

	// oauth routes
	s.echo.POST("/oauth/par", s.handleOauthPar, s.handleOauthMiddleware)
	s.echo.POST("/oauth/token", s.handleOauthToken, s.handleOauthMiddleware)

	// authed
	s.echo.GET("/xrpc/com.atproto.server.getSession", s.handleGetSession, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.refreshSession", s.handleRefreshSession, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.deleteSession", s.handleDeleteSession, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.identity.updateHandle", s.handleIdentityUpdateHandle, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.confirmEmail", s.handleServerConfirmEmail, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.requestEmailConfirmation", s.handleServerRequestEmailConfirmation, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.requestPasswordReset", s.handleServerRequestPasswordReset) // AUTH NOT REQUIRED FOR THIS ONE
	s.echo.POST("/xrpc/com.atproto.server.requestEmailUpdate", s.handleServerRequestEmailUpdate, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.resetPassword", s.handleServerResetPassword, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.updateEmail", s.handleServerUpdateEmail, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)

	// repo
	s.echo.POST("/xrpc/com.atproto.repo.createRecord", s.handleCreateRecord, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.putRecord", s.handlePutRecord, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.deleteRecord", s.handleDeleteRecord, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.applyWrites", s.handleApplyWrites, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.uploadBlob", s.handleRepoUploadBlob, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.importRepo", s.handleRepoImportRepo, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)

	// stupid silly endpoints
	s.echo.GET("/xrpc/app.bsky.actor.getPreferences", s.handleActorGetPreferences, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/app.bsky.actor.putPreferences", s.handleActorPutPreferences, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)

	// are there any routes that we should be allowing without auth? i dont think so but idk
	s.echo.GET("/xrpc/*", s.handleProxy, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/*", s.handleProxy, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)

	// admin routes
	s.echo.POST("/xrpc/com.atproto.server.createInviteCode", s.handleCreateInviteCode, s.handleAdminMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.createInviteCodes", s.handleCreateInviteCodes, s.handleAdminMiddleware)
}

func (s *Server) Serve(ctx context.Context) error {
	s.addRoutes()

	s.logger.Info("migrating...")

	s.db.AutoMigrate(
		&models.Actor{},
		&models.Repo{},
		&models.InviteCode{},
		&models.Token{},
		&models.RefreshToken{},
		&models.Block{},
		&models.Record{},
		&models.Blob{},
		&models.BlobPart{},
		&models.OauthAuthorizationRequest{},
		&models.OauthToken{},
	)

	s.logger.Info("starting cocoon")

	go func() {
		if err := s.httpd.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	go s.backupRoutine()

	for _, relay := range s.config.Relays {
		cli := xrpc.Client{Host: relay}
		atproto.SyncRequestCrawl(ctx, &cli, &atproto.SyncRequestCrawl_Input{
			Hostname: s.config.Hostname,
		})
	}

	<-ctx.Done()

	fmt.Println("shut down")

	return nil
}

func (s *Server) doBackup() {
	start := time.Now()

	s.logger.Info("beginning backup to s3...")

	var buf bytes.Buffer
	if err := func() error {
		s.logger.Info("reading database bytes...")
		s.db.Lock()
		defer s.db.Unlock()

		sf, err := os.Open(s.dbName)
		if err != nil {
			return fmt.Errorf("error opening database for backup: %w", err)
		}
		defer sf.Close()

		if _, err := io.Copy(&buf, sf); err != nil {
			return fmt.Errorf("error reading bytes of backup db: %w", err)
		}

		return nil
	}(); err != nil {
		s.logger.Error("error backing up database", "error", err)
		return
	}

	if err := func() error {
		s.logger.Info("sending to s3...")

		currTime := time.Now().Format("2006-01-02_15-04-05")
		key := "cocoon-backup-" + currTime + ".db"

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
			return err
		}

		svc := s3.New(sess)

		if _, err := svc.PutObject(&s3.PutObjectInput{
			Bucket: aws.String(s.s3Config.Bucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(buf.Bytes()),
		}); err != nil {
			return fmt.Errorf("error uploading file to s3: %w", err)
		}

		s.logger.Info("finished uploading backup to s3", "key", key, "duration", time.Now().Sub(start).Seconds())

		return nil
	}(); err != nil {
		s.logger.Error("error uploading database backup", "error", err)
		return
	}

	os.WriteFile("last-backup.txt", []byte(time.Now().String()), 0644)
}

func (s *Server) backupRoutine() {
	if s.s3Config == nil || !s.s3Config.BackupsEnabled {
		return
	}

	if s.s3Config.Region == "" {
		s.logger.Warn("no s3 region configured but backups are enabled. backups will not run.")
		return
	}

	if s.s3Config.Bucket == "" {
		s.logger.Warn("no s3 bucket configured but backups are enabled. backups will not run.")
		return
	}

	if s.s3Config.AccessKey == "" {
		s.logger.Warn("no s3 access key configured but backups are enabled. backups will not run.")
		return
	}

	if s.s3Config.SecretKey == "" {
		s.logger.Warn("no s3 secret key configured but backups are enabled. backups will not run.")
		return
	}

	shouldBackupNow := false
	lastBackupStr, err := os.ReadFile("last-backup.txt")
	if err != nil {
		shouldBackupNow = true
	} else {
		lastBackup, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", string(lastBackupStr))
		if err != nil {
			shouldBackupNow = true
		} else if time.Now().Sub(lastBackup).Seconds() > 3600 {
			shouldBackupNow = true
		}
	}

	if shouldBackupNow {
		go s.doBackup()
	}

	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		go s.doBackup()
	}
}

func (s *Server) getFilePath(file string) string {
	return fmt.Sprintf("%s/%s", s.config.StaticFilePath, file)
}
