package db

import (
	"sync"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type DB struct {
	cli *gorm.DB
	mu  sync.Mutex
}

func NewDB(cli *gorm.DB) *DB {
	return &DB{
		cli: cli,
		mu:  sync.Mutex{},
	}
}

func (db *DB) Create(value any, clauses []clause.Expression) *gorm.DB {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.cli.Clauses(clauses...).Create(value)
}

func (db *DB) Exec(sql string, clauses []clause.Expression, values ...any) *gorm.DB {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.cli.Clauses(clauses...).Exec(sql, values)
}

func (db *DB) Raw(sql string, clauses []clause.Expression, values ...any) *gorm.DB {
	return db.cli.Clauses(clauses...).Raw(sql, values)
}

func (db *DB) AutoMigrate(models ...any) error {
	return db.cli.AutoMigrate(models...)
}

func (db *DB) Delete(value any, clauses []clause.Expression) *gorm.DB {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.cli.Clauses(clauses...).Delete(value)
}

func (db *DB) First(dest any, conds ...any) *gorm.DB {
	return db.cli.First(dest, conds)
}

// TODO: this isn't actually good. we can commit even if the db is locked here. this is probably okay for the time being, but need to figure
// out a better solution. right now we only do this whenever we're importing a repo though so i'm mostly not worried, but it's still bad.
// e.g. when we do apply writes we should also be using a transcation but we don't right now
func (db *DB) BeginDangerously() *gorm.DB {
	return db.cli.Begin()
}

func (db *DB) Lock() {
	db.mu.Lock()
}

func (db *DB) Unlock() {
	db.mu.Unlock()
}
