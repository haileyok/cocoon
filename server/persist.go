package server

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	indigomodels "github.com/bluesky-social/indigo/models"
	cbg "github.com/whyrusleeping/cbor-gen"
	"gorm.io/gorm"

	"github.com/haileyok/cocoon/models"
)

type DbPersister struct {
	Db *gorm.DB

	Lk  sync.Mutex
	Seq int64

	Broadcast func(*events.XRPCStreamEvent)

	// how long do we actually want to keep these things around
	Retention time.Duration
}

func NewDbPersister(db *gorm.DB, retention time.Duration) (*DbPersister, error) {
	if err := db.AutoMigrate(&models.EventRecord{}); err != nil {
		return nil, fmt.Errorf("failed to migrate EventRecord: %w", err)
	}

	if retention == 0 {
		retention = 72 * time.Hour
	}

	p := &DbPersister{
		Db:        db,
		Retention: retention,
	}

	// kind of hacky. we will try and get the latest one from the db, but if it doesn't exist...well we have a problem
	// because the relay will already have _some_ value > 0 set as a cursor, we'll want to just set this to some high value
	// we'll just grab a current unix timestamp and set that as the cursor
	var lastEvent models.EventRecord
	if err := db.Order("seq desc").Limit(1).First(&lastEvent).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("failed to get last event seq: %w", err)
		}
		p.Seq = time.Now().Unix()
	} else {
		p.Seq = lastEvent.Seq
	}

	go p.cleanupRoutine()

	return p, nil
}

func (p *DbPersister) SetEventBroadcaster(brc func(*events.XRPCStreamEvent)) {
	p.Broadcast = brc
}

func (p *DbPersister) Persist(ctx context.Context, e *events.XRPCStreamEvent) error {
	p.Lk.Lock()
	defer p.Lk.Unlock()

	p.Seq++
	seq := p.Seq

	var did string
	var evtType string

	switch {
	case e.RepoCommit != nil:
		e.RepoCommit.Seq = seq
		did = e.RepoCommit.Repo
		evtType = "commit"
	case e.RepoSync != nil:
		e.RepoSync.Seq = seq
		did = e.RepoSync.Did
		evtType = "sync"
	case e.RepoIdentity != nil:
		e.RepoIdentity.Seq = seq
		did = e.RepoIdentity.Did
		evtType = "identity"
	case e.RepoAccount != nil:
		e.RepoAccount.Seq = seq
		did = e.RepoAccount.Did
		evtType = "account"
	default:
		return fmt.Errorf("unknown event type")
	}

	data, err := serializeEvent(e)
	if err != nil {
		return fmt.Errorf("failed to serialize event: %w", err)
	}

	rec := &models.EventRecord{
		Seq:       seq,
		CreatedAt: time.Now(),
		Did:       did,
		Type:      evtType,
		Data:      data,
	}

	if err := p.Db.Create(rec).Error; err != nil {
		return fmt.Errorf("failed to persist event: %w", err)
	}

	if p.Broadcast != nil {
		p.Broadcast(e)
	}

	return nil
}

func (p *DbPersister) Playback(ctx context.Context, since int64, cb func(*events.XRPCStreamEvent) error) error {
	const pageSize = 500

	cursor := since
	for {
		var records []models.EventRecord
		if err := p.Db.WithContext(ctx).
			Where("seq > ?", cursor).
			Order("seq asc").
			Limit(pageSize).
			Find(&records).Error; err != nil {
			return fmt.Errorf("failed to query events: %w", err)
		}

		if len(records) == 0 {
			return nil
		}

		for _, rec := range records {
			evt, err := deserializeEvent(rec.Type, rec.Data)
			if err != nil {
				return fmt.Errorf("failed to deserialize event %d: %w", rec.Seq, err)
			}

			if err := cb(evt); err != nil {
				return err
			}

			cursor = rec.Seq
		}

		if len(records) < pageSize {
			return nil
		}
	}
}

func (p *DbPersister) TakeDownRepo(ctx context.Context, uid indigomodels.Uid) error {
	return nil
}

func (p *DbPersister) Flush(ctx context.Context) error {
	return nil
}

func (p *DbPersister) Shutdown(ctx context.Context) error {
	return nil
}

func (p *DbPersister) cleanupRoutine() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-p.Retention)
		if err := p.Db.Where("created_at < ?", cutoff).Delete(&models.EventRecord{}).Error; err != nil {
			continue
		}
	}
}

func serializeEvent(e *events.XRPCStreamEvent) ([]byte, error) {
	buf := new(bytes.Buffer)
	cw := cbg.NewCborWriter(buf)

	switch {
	case e.RepoCommit != nil:
		if err := e.RepoCommit.MarshalCBOR(cw); err != nil {
			return nil, err
		}
	case e.RepoSync != nil:
		if err := e.RepoSync.MarshalCBOR(cw); err != nil {
			return nil, err
		}
	case e.RepoIdentity != nil:
		if err := e.RepoIdentity.MarshalCBOR(cw); err != nil {
			return nil, err
		}
	case e.RepoAccount != nil:
		if err := e.RepoAccount.MarshalCBOR(cw); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown event type")
	}

	return buf.Bytes(), nil
}

func deserializeEvent(evtType string, data []byte) (*events.XRPCStreamEvent, error) {
	r := bytes.NewReader(data)
	cr := cbg.NewCborReader(r)

	switch evtType {
	case "commit":
		evt := &atproto.SyncSubscribeRepos_Commit{}
		if err := evt.UnmarshalCBOR(cr); err != nil {
			return nil, err
		}
		return &events.XRPCStreamEvent{RepoCommit: evt}, nil
	case "sync":
		evt := &atproto.SyncSubscribeRepos_Sync{}
		if err := evt.UnmarshalCBOR(cr); err != nil {
			return nil, err
		}
		return &events.XRPCStreamEvent{RepoSync: evt}, nil
	case "identity":
		evt := &atproto.SyncSubscribeRepos_Identity{}
		if err := evt.UnmarshalCBOR(cr); err != nil {
			return nil, err
		}
		return &events.XRPCStreamEvent{RepoIdentity: evt}, nil
	case "account":
		evt := &atproto.SyncSubscribeRepos_Account{}
		if err := evt.UnmarshalCBOR(cr); err != nil {
			return nil, err
		}
		return &events.XRPCStreamEvent{RepoAccount: evt}, nil
	default:
		return nil, fmt.Errorf("unknown event type: %s", evtType)
	}
}
