package db

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type DB struct {
	cli *gorm.DB
}

func NewDB(cli *gorm.DB) *DB {
	return &DB{
		cli: cli,
	}
}

func (db *DB) Create(ctx context.Context, value any, clauses []clause.Expression) *gorm.DB {
	return db.cli.WithContext(ctx).Clauses(clauses...).Create(value)
}

func (db *DB) Save(ctx context.Context, value any, clauses []clause.Expression) *gorm.DB {
	return db.cli.WithContext(ctx).Clauses(clauses...).Save(value)
}

func (db *DB) Exec(ctx context.Context, sql string, clauses []clause.Expression, values ...any) *gorm.DB {
	return db.cli.WithContext(ctx).Clauses(clauses...).Exec(sql, values...)
}

func (db *DB) Raw(ctx context.Context, sql string, clauses []clause.Expression, values ...any) *gorm.DB {
	return db.cli.WithContext(ctx).Clauses(clauses...).Raw(sql, values...)
}

func (db *DB) AutoMigrate(models ...any) error {
	return db.cli.AutoMigrate(models...)
}

func (db *DB) Delete(ctx context.Context, value any, clauses []clause.Expression) *gorm.DB {
	return db.cli.WithContext(ctx).Clauses(clauses...).Delete(value)
}

func (db *DB) First(ctx context.Context, dest any, conds ...any) *gorm.DB {
	return db.cli.WithContext(ctx).First(dest, conds...)
}

func (db *DB) Begin(ctx context.Context) *gorm.DB {
	return db.cli.WithContext(ctx).Begin()
}

func (db *DB) Client() *gorm.DB {
	return db.cli
}
