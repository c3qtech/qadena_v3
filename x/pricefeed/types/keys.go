package types

const (
	// ModuleName defines the module name
	ModuleName = "pricefeed"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_pricefeed"
)

var (
	ParamsKey = []byte("p_pricefeed")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
