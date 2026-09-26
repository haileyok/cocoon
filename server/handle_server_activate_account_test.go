package server

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/models"
)

func TestActivateAccountValidatesDID(t *testing.T) {
	for _, method := range []string{"plc", "web"} {
		for _, scenario := range []string{"valid", "endpoint", "signing", "rotation", "unavailable", "malformed"} {
			t.Run(method+"/"+scenario, func(t *testing.T) {
				s := newTestServer(t)
				persister, err := NewDbPersister(s.db.Client(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				s.evtman = events.NewEventManager(persister)
				account := s.createTestAccount(t, "activation.pds.test")
				if method == "web" {
					for _, model := range []any{&models.Repo{}, &models.Actor{}} {
						if err := s.db.Client().Model(model).Where("did = ?", account.Did).Update("did", "did:web:identity.test").Error; err != nil {
							t.Fatal(err)
						}
					}
					account.Did = "did:web:identity.test"
				}
				s.seedGenesisRepo(t, account.Did, account.SigningKey)
				if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Update("deactivated", true).Error; err != nil {
					t.Fatal(err)
				}
				attachStatusDID(t, s, account, account.Did, scenario)
				before := mustRepoActor(t, s, account.Did)
				session, err := s.createSession(context.Background(), &before.Repo)
				if err != nil {
					t.Fatal(err)
				}
				c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.activateAccount", "{}", map[string]string{"Authorization": "Bearer " + session.AccessToken})
				handler := s.handleLegacySessionMiddleware(s.handleOauthSessionMiddleware(s.handleServerActivateAccount))
				if err := handler(c); err != nil {
					t.Fatal(err)
				}
				after := mustRepoActor(t, s, account.Did)
				types := eventTypesFor(t, s, account.Did)
				if scenario == "valid" || (method == "web" && scenario == "rotation") {
					if w.Code != 200 || !after.Repo.Active() {
						t.Fatalf("activation: %d %s; active=%t", w.Code, w.Body.String(), after.Repo.Active())
					}
					if !reflect.DeepEqual(types, []string{"account", "identity", "sync"}) {
						t.Fatalf("activation events: %v", types)
					}
				} else {
					if w.Code != 400 {
						t.Errorf("rejection: %d %s", w.Code, w.Body.String())
					}
					if !reflect.DeepEqual(before, after) {
						t.Error("rejected activation changed account state")
					}
					if len(types) != 0 {
						t.Errorf("rejected activation emitted events: %v", types)
					}
				}
			})
		}
	}
}
