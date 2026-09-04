// shamirtool -- split a file into Shamir shares, or reassemble it.
//
// Uses github.com/hashicorp/vault/shamir, which is ALREADY VENDORED and already load-bearing in
// this chain: cmd/qadenad_enclave uses it for SS key re-sharing, and x/qadena's protect-key /
// recover-key features are built on it.  So this adds no dependency, and the algorithm is the one
// the chain itself relies on.
//
// COMBINE DOES NOT VERIFY THE THRESHOLD.  Given too few shares it returns GARBAGE and no error --
// measured, not assumed.  So `combine` here checks the reassembled bytes against a SHA-256 recorded
// at split time and fails loudly on mismatch.  Without that check a recovery cannot tell "restored"
// from "restored nonsense", which is the worst possible failure for a backup tool.
//
//   go run ./foundation_scripts/shamirtool split   --in <file> --out-dir <dir> --parts 5 --threshold 3
//   go run ./foundation_scripts/shamirtool combine --out <file> <share>...
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/shamir"
)

const magic = "QADENA-SHAMIR-SHARE-v1"

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func main() {
	if len(os.Args) < 2 {
		die("usage: shamirtool split|combine ...")
	}
	switch os.Args[1] {
	case "split":
		doSplit(os.Args[2:])
	case "combine":
		doCombine(os.Args[2:])
	default:
		die("unknown subcommand %q (want split or combine)", os.Args[1])
	}
}

func doSplit(args []string) {
	fs := flag.NewFlagSet("split", flag.ExitOnError)
	in := fs.String("in", "", "file to split")
	outDir := fs.String("out-dir", "", "directory to write shares into")
	parts := fs.Int("parts", 5, "how many shares to produce")
	thr := fs.Int("threshold", 3, "how many shares are needed to reassemble")
	label := fs.String("label", "", "free text recorded in each share header")
	fs.Parse(args)
	if *in == "" || *outDir == "" {
		die("split needs --in and --out-dir")
	}
	if *thr < 2 || *thr > *parts {
		die("threshold must be between 2 and parts (%d)", *parts)
	}
	secret, err := os.ReadFile(*in)
	if err != nil {
		die("cannot read %s: %v", *in, err)
	}
	if len(secret) == 0 {
		die("%s is empty -- refusing to split nothing", *in)
	}
	sum := sha256.Sum256(secret)
	digest := hex.EncodeToString(sum[:])

	shares, err := shamir.Split(secret, *parts, *thr)
	if err != nil {
		die("split failed: %v", err)
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		die("cannot create %s: %v", *outDir, err)
	}
	for i, sh := range shares {
		p := filepath.Join(*outDir, fmt.Sprintf("share-%02d-of-%02d.txt", i+1, *parts))
		// The header is plain text on purpose: a share that outlives the tooling should still say
		// what it is, what it needs, and what it should reassemble into.
		body := fmt.Sprintf("%s\nindex: %d\nparts: %d\nthreshold: %d\nsha256: %s\nlabel: %s\n"+
			"# Any %d of the %d shares reassemble the original.  Fewer produce GARBAGE SILENTLY,\n"+
			"# which is why sha256 is recorded here and checked on combine.\n%s\n",
			magic, i+1, *parts, *thr, digest, *label, *thr, *parts,
			base64.StdEncoding.EncodeToString(sh))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			die("cannot write %s: %v", p, err)
		}
		fmt.Printf("  wrote %s\n", p)
	}
	fmt.Printf("\n  %d shares, any %d reassemble.  sha256 of the original: %s\n", *parts, *thr, digest)
}

func doCombine(args []string) {
	fs := flag.NewFlagSet("combine", flag.ExitOnError)
	out := fs.String("out", "", "file to write the reassembled secret to")
	fs.Parse(args)
	files := fs.Args()
	if *out == "" || len(files) == 0 {
		die("combine needs --out and at least one share file")
	}
	var shares [][]byte
	var want, thr string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			die("cannot read %s: %v", f, err)
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) == 0 || !strings.HasPrefix(lines[0], magic) {
			die("%s is not a %s file", f, magic)
		}
		var payload string
		for _, l := range lines[1:] {
			switch {
			case strings.HasPrefix(l, "sha256: "):
				d := strings.TrimSpace(strings.TrimPrefix(l, "sha256: "))
				if want != "" && want != d {
					die("%s belongs to a DIFFERENT secret (sha256 %s vs %s)", f, d, want)
				}
				want = d
			case strings.HasPrefix(l, "threshold: "):
				thr = strings.TrimSpace(strings.TrimPrefix(l, "threshold: "))
			case strings.HasPrefix(l, "#"), l == "":
			case strings.Contains(l, ": "):
			default:
				payload = l
			}
		}
		if payload == "" {
			die("%s has no share payload", f)
		}
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			die("%s: payload is not valid base64: %v", f, err)
		}
		shares = append(shares, raw)
	}
	if n, err := strconv.Atoi(thr); err == nil && len(shares) < n {
		die("only %d share(s) given but %s are required -- combine would return GARBAGE, not an error", len(shares), thr)
	}
	got, err := shamir.Combine(shares)
	if err != nil {
		die("combine failed: %v", err)
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != want {
		die("REASSEMBLED DATA IS WRONG: sha256 %s, expected %s\n"+
			"The shares are valid but do not belong together, or one is corrupt.",
			hex.EncodeToString(sum[:]), want)
	}
	if err := os.WriteFile(*out, got, 0o600); err != nil {
		die("cannot write %s: %v", *out, err)
	}
	fmt.Printf("  reassembled %d bytes -> %s  (sha256 verified)\n", len(got), *out)
}
