package server

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
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

func TestAccountStatusWaitsForRepoWrite(t *testing.T) {
	for _, activate := range []bool{true, false} {
		t.Run(map[bool]string{true: "activate", false: "deactivate"}[activate], func(t *testing.T) {
			s := newTestServer(t)
			s.repoman = NewRepoMan(s)
			manager, persister := newTestEvtmanPersister(t)
			s.evtman = manager
			account := s.createTestAccount(t, "status.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			attachStatusDID(t, s, account, account.Did, "valid")
			if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Update("deactivated", activate).Error; err != nil {
				t.Fatal(err)
			}
			repo := mustRepoActor(t, s, account.Did)
			c, w := newRequestContext("POST", "/", "{}", nil)
			c.Set("repo", repo)
			paused, resume := make(chan struct{}), make(chan struct{})
			if err := s.db.Client().Callback().Raw().Before("gorm:raw").Register("pause-head", func(tx *gorm.DB) {
				if tx.Statement.SQL.String() == "UPDATE repos SET root = ?, rev = ? WHERE did = ?" {
					close(paused)
					<-resume
				}
			}); err != nil {
				t.Fatal(err)
			}
			writeDone := make(chan error, 1)
			go func() {
				_, err := s.repoman.applyWrites(context.Background(), repo.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("staged"), Record: rmPostRecord("staged")}}, nil)
				writeDone <- err
			}()
			select {
			case <-paused:
			case err := <-writeDone:
				t.Fatalf("write did not reach head update: %v", err)
			case <-time.After(5 * time.Second):
				close(resume)
				t.Fatal("write did not reach head update")
			}
			statusDone := make(chan error, 1)
			go func() {
				if activate {
					statusDone <- s.handleServerActivateAccount(c)
				} else {
					statusDone <- s.handleServerDeactivateAccount(c)
				}
			}()
			select {
			case err := <-statusDone:
				close(resume)
				<-writeDone
				t.Fatalf("status changed before the write completed: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(resume)
			writeErr, statusErr := <-writeDone, <-statusDone
			if writeErr != nil || statusErr != nil || w.Code != 200 {
				t.Fatalf("write: %v; status: %v (%d)", writeErr, statusErr, w.Code)
			}
			var got []*events.XRPCStreamEvent
			if err := persister.Playback(context.Background(), 0, func(evt *events.XRPCStreamEvent) error {
				got = append(got, evt)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if activate {
				if len(got) != 3 || got[2].RepoSync == nil || got[2].RepoSync.Rev != currentRev(t, s, account.Did) {
					t.Fatal("activation did not announce the completed write")
				}
			} else if len(got) != 2 || got[0].RepoCommit == nil || got[1].RepoAccount == nil || got[1].RepoAccount.Active {
				t.Fatal("expected the completed commit before the deactivation event")
			}
		})
	}
}
