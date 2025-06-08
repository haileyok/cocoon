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
	return db.cli.Clauses(clauses...).Create(&db)
}

func (db *DB) Exec(sql string, clauses []clause.Expression, values ...any) *gorm.DB {
	return db.cli.Clauses(clauses...).Exec(sql, values)
}

func (db *DB) Raw(sql string, clauses []clause.Expression, values ...any) *gorm.DB {
	db.mu.Lock()
	defer db.mu.Unlock()
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
