package server

import (
	"fmt"
	"log/slog"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type DBConfig struct {
	// Name is the sqlite file or the name of the postgres database
	Name     string
	Type     string
	URL      string
	User     string
	Password string
	Host     string
	Port     uint
	Custom   string
}

func (cfg *DBConfig) Connect(logger *slog.Logger) (*gorm.DB, error) {
	dbType := cfg.Type
	if dbType == "" {
		dbType = "sqlite"
	}

	var gdb *gorm.DB
	var err error
	switch dbType {
	case "postgres":
		var dsn string
		if cfg.URL != "" {
			dsn = cfg.URL
		} else if cfg.Host != "" &&
			cfg.User != "" &&
			cfg.Password != "" &&
			cfg.Name != "" {
			dsn = fmt.Sprintf(
				"host=%s port=%d user=%s password=%s dbname=%s %s",
				cfg.Host,
				cfg.Port,
				cfg.User,
				cfg.Password,
				cfg.Name,
				cfg.Custom,
			)
		} else {
			return nil, fmt.Errorf("database config must be set when using postgres")
		}
		gdb, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		if logger != nil {
			logger.Info("connected to PostgreSQL database", "host", cfg.Host, "dbname", cfg.Name)
		}
	case "sqlite":
		gdb, err = gorm.Open(sqlite.Open(cfg.Name), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to open sqlite database: %w", err)
		}
		gdb.Exec("PRAGMA journal_mode=WAL")
		gdb.Exec("PRAGMA synchronous=NORMAL")

		if logger != nil {
			logger.Info("connected to SQLite database", "path", cfg.Name)
		}
	default:
		panic("UNSUPPORTED DB TYPE")
	}
	return gdb, nil
}
