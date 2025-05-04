package types

const (
	// ModuleName defines the module name
	ModuleName = "dsvs"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_dsvs"
)

var (
	ParamsKey = []byte("p_dsvs")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
