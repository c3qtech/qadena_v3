package common

import "testing"

// The gate these assert on decides whether x/qadena emits ANY debug logging. It is set from
// config.toml's log_level, which on this fleet had to become a per-module override list so the
// p2p/consensus/mempool firehose could be quieted without also losing the enclave's output --
// 92% of a node's log volume, which filled every disk on 2026-08-22.
//
// The old implementation switched on the whole string, so every list form fell through to default
// and turned debug OFF. The cases marked NEGATIVE CONTROL below fail against it; that is the point
// of them. Setting a level whose wildcard reads "debug" and getting silence is not a degraded
// outcome, it is the opposite of the instruction, and nothing reports it.
func TestSetLogLevel(t *testing.T) {
	cases := []struct {
		name  string
		level string
		want  bool
	}{
		{"plain debug", "debug", true},
		{"plain info", "info", false},
		{"plain error", "error", false},
		{"empty is not debug", "", false},
		{"case insensitive", "DeBuG", true},
		{"surrounding space", "  debug  ", true},

		// NEGATIVE CONTROLS -- each of these returned false before the fix.
		{"wildcard debug", "*:debug", true},
		// VERBATIM FROM config/config.yml.  If that line changes, this case must change with it:
		// the whole point is that the level the fleet actually runs still enables enclave debug.
		{"the fleet's level", "p2p:info,consensus:info,mempool:info,server:info,*:debug", true},
		// The string 8f8a1729 suggested, kept because it is quoted in that commit and in
		// run_enclave_standalone.sh's comment; `server` was added to the deployed one after its own
		// measurement put server second at 21.9%.
		{"the level 8f8a1729 suggested", "p2p:info,consensus:info,mempool:info,*:debug", true},
		{"wildcard debug listed first", "*:debug,p2p:info", true},
		{"spaces around entries", "p2p:info , *:debug", true},
		{"no wildcard, one debug entry", "p2p:info,server:debug", true},

		// The wildcard governs even when another module names debug, because this gate is global
		// and a per-module entry cannot speak for x/qadena's lines.
		{"wildcard info beats a module debug", "server:debug,*:info", false},
		{"all info", "p2p:info,consensus:info,*:info", false},
		{"malformed entry ignored", "notakeyvalue,*:debug", true},
		{"no wildcard and no debug", "p2p:info,server:error", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			LogLevelDebugEnabled = !tc.want // start from the wrong value so a no-op fails
			SetLogLevel(tc.level)
			if LogLevelDebugEnabled != tc.want {
				t.Fatalf("SetLogLevel(%q): debug enabled = %v, want %v", tc.level, LogLevelDebugEnabled, tc.want)
			}
		})
	}
}
