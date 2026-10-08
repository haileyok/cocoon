package server

import (
	"encoding/json"
	"strings"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// com.atproto.simplespace.*: spaces governed by the account that is their
// authority, following the reference PDS (packages/pds/src/simplespace and
// api/com/atproto/simplespace) at bluesky-social/atproto 5b95b2f2.

const (
	policyPublic      = "public"
	policyMemberList  = "member-list"
	policyManagingApp = "managing-app"
	appAccessOpen     = "open"
	appAccessAllow    = "allowList"
)

type lexUnion struct {
	Type        string   `json:"$type"`
	ManagingApp *string  `json:"managingApp,omitempty"`
	Allowed     []string `json:"allowed,omitempty"`
}

func policyToDB(raw json.RawMessage) (string, *string, error) {
	var u lexUnion
	if err := json.Unmarshal(raw, &u); err != nil {
		return "", nil, errInvalid("", "Invalid policy")
	}
	switch u.Type {
	case "com.atproto.simplespace.defs#publicPolicy":
		return policyPublic, nil, nil
	case "com.atproto.simplespace.defs#memberListPolicy":
		return policyMemberList, nil, nil
	case "com.atproto.simplespace.defs#managingAppPolicy":
		if u.ManagingApp == nil {
			return "", nil, errInvalid("", "managingAppPolicy must have the property \"managingApp\"")
		}
		if !strings.HasPrefix(*u.ManagingApp, "did:") {
			return "", nil, errInvalid("UnsupportedPolicy", "managingApp must be a DID with an optional service fragment, got: %s", *u.ManagingApp)
		}
		app := *u.ManagingApp
		return policyManagingApp, &app, nil
	}
	return "", nil, errInvalid("UnsupportedPolicy", "Unsupported policy: %s", u.Type)
}

func appAccessToDB(raw json.RawMessage) (string, string, error) {
	var u lexUnion
	if err := json.Unmarshal(raw, &u); err != nil {
		return "", "", errInvalid("", "Invalid appAccess")
	}
	switch u.Type {
	case "com.atproto.simplespace.defs#open":
		return appAccessOpen, "[]", nil
	case "com.atproto.simplespace.defs#allowList":
		if u.Allowed == nil {
			return "", "", errInvalid("", "allowList must have the property \"allowed\"")
		}
		b, _ := json.Marshal(u.Allowed)
		return appAccessAllow, string(b), nil
	}
	return "", "", errInvalid("UnsupportedAppAccess", "Unsupported appAccess: %s", u.Type)
}

func policyToLex(policy string, app *string) map[string]any {
	switch policy {
	case policyPublic:
		return map[string]any{"$type": "com.atproto.simplespace.defs#publicPolicy"}
	case policyManagingApp:
		a := ""
		if app != nil {
			a = *app
		}
		return map[string]any{"$type": "com.atproto.simplespace.defs#managingAppPolicy", "managingApp": a}
	}
	return map[string]any{"$type": "com.atproto.simplespace.defs#memberListPolicy"}
}

func configToLex(cfg *models.SimplespaceConfig) map[string]any {
	appAccess := map[string]any{"$type": "com.atproto.simplespace.defs#open"}
	if cfg.AppAccessType == appAccessAllow {
		var allowed []string
		_ = json.Unmarshal([]byte(cfg.AppAllowed), &allowed)
		if allowed == nil {
			allowed = []string{}
		}
		appAccess = map[string]any{"$type": "com.atproto.simplespace.defs#allowList", "allowed": allowed}
	}
	return map[string]any{
		"uri":         cfg.Uri,
		"readPolicy":  policyToLex(cfg.ReadPolicy, cfg.ReadManagingApp),
		"writePolicy": policyToLex(cfg.WritePolicy, cfg.WriteManagingApp),
		"appAccess":   appAccess,
	}
}

func (s *Server) handleSimplespaceCreateSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in struct {
			SpaceType   string          `json:"spaceType"`
			Skey        string          `json:"skey"`
			ReadPolicy  json.RawMessage `json:"readPolicy"`
			WritePolicy json.RawMessage `json:"writePolicy"`
			AppAccess   json.RawMessage `json:"appAccess"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		if _, err := parseNSIDParam("spaceType", in.SpaceType, true); err != nil {
			return nil, err
		}
		if in.Skey == "" {
			in.Skey = nextTID("")
		}
		if _, err := parseRkeyParam("skey", in.Skey, true); err != nil {
			return nil, err
		}
		ref := space.Ref{Authority: a.did, Type: in.SpaceType, Skey: in.Skey}
		if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Manage: "create"}); err != nil {
			return nil, err
		}
		cfg := models.SimplespaceConfig{ReadPolicy: policyMemberList, WritePolicy: policyMemberList, AppAccessType: appAccessOpen, AppAllowed: "[]"}
		if len(in.ReadPolicy) > 0 {
			if cfg.ReadPolicy, cfg.ReadManagingApp, err = policyToDB(in.ReadPolicy); err != nil {
				return nil, err
			}
		}
		if len(in.WritePolicy) > 0 {
			if cfg.WritePolicy, cfg.WriteManagingApp, err = policyToDB(in.WritePolicy); err != nil {
				return nil, err
			}
		}
		if len(in.AppAccess) > 0 {
			if cfg.AppAccessType, cfg.AppAllowed, err = appAccessToDB(in.AppAccess); err != nil {
				return nil, err
			}
		}
		err = s.db.Client().WithContext(e.Request().Context()).Transaction(func(tx *gorm.DB) error {
			st := s.spaceStore(tx, a.did)
			existing, err := st.getSpaceConfig(ref.String())
			if err != nil {
				return err
			}
			if existing != nil {
				return errInvalid("SpaceAlreadyExists", "Space already exists")
			}
			return st.createSpace(ref, cfg)
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"uri": ref.String()}, nil
	}()
	return writeSpaceResult(e, body, err)
}

type memberInput struct {
	Space string `json:"space"`
	Did   string `json:"did"`
	Read  *bool  `json:"read"`
	Write *bool  `json:"write"`
}

func (s *Server) handleSimplespacePutMember(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in memberInput
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if _, err := parseDIDParam("did", in.Did); err != nil {
			return nil, err
		}
		if in.Read == nil || in.Write == nil {
			return nil, errInvalid("", "Input must have the properties \"read\" and \"write\"")
		}
		if err := assertSpaceOwner(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		return nil, s.db.Client().WithContext(e.Request().Context()).Transaction(func(tx *gorm.DB) error {
			st := s.spaceStore(tx, a.did)
			if _, err := st.getActiveSpaceConfig(ref.String()); err != nil {
				return err
			}
			return st.putMember(ref.String(), in.Did, *in.Read, *in.Write)
		})
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSimplespaceRemoveMember(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in memberInput
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if _, err := parseDIDParam("did", in.Did); err != nil {
			return nil, err
		}
		if err := assertSpaceOwner(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		return nil, s.db.Client().WithContext(e.Request().Context()).Transaction(func(tx *gorm.DB) error {
			st := s.spaceStore(tx, a.did)
			if _, err := st.getActiveSpaceConfig(ref.String()); err != nil {
				return err
			}
			return st.removeMember(ref.String(), in.Did)
		})
	}()
	return writeSpaceResult(e, body, err)
}
