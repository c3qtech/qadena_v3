package types

const (
	// ModuleName defines the module name
	ModuleName = "nameservice"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_nameservice"
)

var (
	ParamsKey = []byte("p_nameservice")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
