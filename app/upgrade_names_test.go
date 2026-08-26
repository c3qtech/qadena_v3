package app

// The plan-name set decides which binaries HALT at an upgrade height and which APPLY it, so the
// four sources and their dedup are worth locking down without constructing an app.  The scenarios
// mirror the three node kinds that exist in practice: a builder's binary, a node restarting after
// an upgrade, and a state-synced joiner with no disk history.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpgradeHandlerNames(t *testing.T) {
	cases := map[string]struct {
		version    string
		historical []string
		diskName   string
		want       []string
	}{
		"a normal release build": {
			version: "1.1.23",
			want:    []string{UpgradeName, "v1.1.23"},
		},
		"plain go build, no ldflags": {
			// No version-named handler: this binary will HALT at a version-named height rather
			// than apply it half-configured, and RegisterUpgradeHandlers logs why.
			version: "",
			want:    []string{UpgradeName},
		},
		"restart after applying a plan": {
			version:  "1.1.24",
			diskName: "v1.1.23",
			want:     []string{UpgradeName, "v1.1.23", "v1.1.24"},
		},
		"state-synced joiner, no disk file": {
			version:    "1.1.24",
			historical: []string{"v1.1.23"},
			want:       []string{UpgradeName, "v1.1.23", "v1.1.24"},
		},
		"every source names the same plan": {
			// Immediately after applying v1.1.23 on a v1.1.23 binary with the list maintained,
			// three sources collide; SetUpgradeHandler must be called once per name.
			version:    "1.1.23",
			historical: []string{"v1.1.23"},
			diskName:   "v1.1.23",
			want:       []string{UpgradeName, "v1.1.23"},
		},
		"empty strings never register": {
			version:    "",
			historical: []string{""},
			diskName:   "",
			want:       []string{UpgradeName},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, upgradeHandlerNames(tc.version, tc.historical, tc.diskName))
		})
	}
}
