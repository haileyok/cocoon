package server

import (
	"github.com/haileyok/cocoon/sqlite_blockstore"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
)

type BlockstoreVariant int

const (
	BlockstoreVariantSqlite = iota
)

func MustReturnBlockstoreVariant(maybeBsv string) BlockstoreVariant {
	switch maybeBsv {
	case "sqlite":
		return BlockstoreVariantSqlite
	default:
		panic("invalid blockstore variant provided")
	}
}

func (s *Server) getBlockstore(did string) blockstore.Blockstore {
	switch s.config.BlockstoreVariant {
	case BlockstoreVariantSqlite:
		return sqlite_blockstore.New(did, s.db)
	default:
		return sqlite_blockstore.New(did, s.db)
	}
}
