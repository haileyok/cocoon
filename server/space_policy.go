package server

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// Space policies, following the reference PDS's space-policy/policy.ts at
// bluesky-social/atproto d4def6e9. A space is governed by one policy: an open
// union discriminated by $type, which both selects the policy and carries its
// configuration. Every PDS supports the three baseline policies.

const (
	policyPersonal = "com.atproto.personalspace.policy"
	policyMember   = "com.atproto.memberspace.policy"
	policyManaged  = "com.atproto.managedspace.policy"
)

// spacePolicy is a baseline policy with its defaults filled in, so that what
// is stored is exactly what is enforced.
type spacePolicy struct {
	Type string
	// memberspace
	PublicRead     bool
	PublicWrite    bool
	AllowedApps    []string // nil when unset
	PublishMembers bool
	// memberspace and managedspace
	PublishPolicy bool
	// managedspace: a did#serviceId reference
	ManagingApp string
}

func (p *spacePolicy) isMember() bool  { return p.Type == policyMember }
func (p *spacePolicy) isManaged() bool { return p.Type == policyManaged }

// lex is the policy as a Lexicon object.
func (p *spacePolicy) lex() map[string]any {
	switch p.Type {
	case policyMember:
		out := map[string]any{
			"$type":          p.Type,
			"publicRead":     p.PublicRead,
			"publicWrite":    p.PublicWrite,
			"publishPolicy":  p.PublishPolicy,
			"publishMembers": p.PublishMembers,
		}
		if p.AllowedApps != nil {
			apps := make([]any, len(p.AllowedApps))
			for i, a := range p.AllowedApps {
				apps[i] = a
			}
			out["allowedApps"] = apps
		}
		return out
	case policyManaged:
		return map[string]any{"$type": p.Type, "managingApp": p.ManagingApp, "publishPolicy": p.PublishPolicy}
	}
	return map[string]any{"$type": policyPersonal}
}

func (p *spacePolicy) marshal() (string, error) {
	b, err := json.Marshal(p.lex())
	return string(b), err
}

// parseStoredPolicy reads a policy this host stored.
func parseStoredPolicy(s string) (*spacePolicy, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, fmt.Errorf("stored space policy is malformed: %w", err)
	}
	// Not held to the rules for new policies: a space whose managing app was
	// stored as a bare DID before it had to be a did#serviceId reference can't
	// reach its app, and fails as an upstream failure until its policy is
	// updated.
	p, err := buildPolicy(raw, false)
	if err != nil {
		return nil, fmt.Errorf("stored space policy is invalid: %w", err)
	}
	return p, nil
}

// normalizePolicy checks that this host implements a requested policy, and
// fills in its defaults. Unknown fields are dropped, as Lexicon evolution
// allows. A change that can't safely be ignored comes as a new policy rather
// than a new field.
func normalizePolicy(raw map[string]any) (*spacePolicy, error) {
	return buildPolicy(raw, true)
}

func buildPolicy(raw map[string]any, strict bool) (*spacePolicy, error) {
	typ, ok := raw["$type"].(string)
	if !ok || typ == "" {
		return nil, errInvalid("", "Input/policy must be an object which includes the \"$type\" property")
	}
	switch typ {
	case policyPersonal:
		return &spacePolicy{Type: typ}, nil
	case policyMember:
		p := &spacePolicy{Type: typ}
		var err error
		if p.PublicRead, err = policyBool(raw, "publicRead"); err != nil {
			return nil, err
		}
		if p.PublicWrite, err = policyBool(raw, "publicWrite"); err != nil {
			return nil, err
		}
		if p.PublishPolicy, err = policyBool(raw, "publishPolicy"); err != nil {
			return nil, err
		}
		if p.PublishMembers, err = policyBool(raw, "publishMembers"); err != nil {
			return nil, err
		}
		if v, present := raw["allowedApps"]; present && v != nil {
			list, ok := v.([]any)
			if !ok {
				return nil, errInvalid("", "policy/allowedApps must be an array")
			}
			p.AllowedApps = make([]string, 0, len(list))
			for _, item := range list {
				s, ok := item.(string)
				if !ok {
					return nil, errInvalid("", "policy/allowedApps must be an array of URIs")
				}
				if _, err := syntax.ParseURI(s); err != nil {
					return nil, errInvalid("", "policy/allowedApps must be an array of URIs, got: %s", s)
				}
				p.AllowedApps = append(p.AllowedApps, s)
			}
		}
		return p, nil
	case policyManaged:
		app, ok := raw["managingApp"].(string)
		if !ok {
			return nil, errInvalid("", "managedspace policy must have the property \"managingApp\"")
		}
		if strict && !isDIDServiceRef(app) {
			return nil, errInvalid("", "managingApp must be a did#serviceId reference, got: %s", app)
		}
		p := &spacePolicy{Type: typ, ManagingApp: app}
		var err error
		if p.PublishPolicy, err = policyBool(raw, "publishPolicy"); err != nil {
			return nil, err
		}
		return p, nil
	}
	return nil, errInvalid("UnsupportedPolicy", "Unsupported policy: %s", typ)
}

func policyBool(raw map[string]any, key string) (bool, error) {
	v, present := raw[key]
	if !present || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, errInvalid("", "policy/%s must be a boolean", key)
	}
	return b, nil
}

// isDIDServiceRef reports whether s is an absolute DID reference: a DID
// followed by #serviceId.
func isDIDServiceRef(s string) bool {
	did, frag, ok := strings.Cut(s, "#")
	if !ok || frag == "" || strings.ContainsAny(frag, "# \t\r\n") {
		return false
	}
	_, err := syntax.ParseDID(did)
	return err == nil
}

// parseArchivedPolicy validates a policy from a space meta archive, which no
// lexicon has checked yet, then normalizes it as normalizePolicy does.
func parseArchivedPolicy(raw map[string]any) (*spacePolicy, error) {
	p, err := normalizePolicy(raw)
	if err != nil {
		if xe, ok := err.(*xrpcError); ok && xe.Name == "InvalidRequest" {
			return nil, errInvalid("InvalidSpaceMeta", "Invalid policy: %s", xe.Message)
		}
		return nil, err
	}
	return p, nil
}

func (p *spacePolicy) assertMemberspace() error {
	if !p.isMember() {
		return errInvalid("PolicyMismatch", "Space is not governed by the memberspace policy")
	}
	return nil
}

func (p *spacePolicy) policyPublished() bool {
	return (p.isMember() || p.isManaged()) && p.PublishPolicy
}

func (p *spacePolicy) membersPublished() bool { return p.isMember() && p.PublishMembers }

// appAuthorized: only memberspace restricts apps. Evaluated against the
// attested client_id, so an app that presents no client attestation is never
// one of the allowed apps.
func (p *spacePolicy) appAuthorized(clientID string) bool {
	if !p.isMember() || p.AllowedApps == nil {
		return true
	}
	if clientID == "" {
		return false
	}
	for _, a := range p.AllowedApps {
		if a == clientID {
			return true
		}
	}
	return false
}

// legacyConfigToPolicy converts a pre-October 29 simplespace config to a
// baseline policy, as the reference's actor store migration 006 does. A
// managing app on either side becomes a managedspace, which asks the app about
// both reads and writes. Anything else becomes a memberspace. Only memberspace
// restricts apps, so a managedspace drops any app allow-list.
func legacyConfigToPolicy(readPolicy string, readApp *string, writePolicy string, writeApp *string, appAccess, appAllowed string) *spacePolicy {
	app := readApp
	if app == nil {
		app = writeApp
	}
	if app != nil && *app != "" {
		return &spacePolicy{Type: policyManaged, ManagingApp: *app}
	}
	p := &spacePolicy{Type: policyMember, PublicRead: readPolicy == "public", PublicWrite: writePolicy == "public"}
	if appAccess == "allowList" {
		var allowed []string
		if json.Unmarshal([]byte(appAllowed), &allowed) == nil {
			if allowed == nil {
				allowed = []string{}
			}
			p.AllowedApps = allowed
		}
	}
	return p
}
