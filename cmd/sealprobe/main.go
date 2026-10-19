// sealprobe -- can a DIFFERENT binary, signed with the repo key, open this node's sealed params?
//
// WHY THIS EXISTS.  enclave_config/enclave_params_<uid>.json is sealed with the PRODUCT key, which
// SGX derives from MRSIGNER + productID -- not from the measurement.  The signing key ships in the
// repo (cmd/qadenad_enclave/private.pem).  So the question "could someone build their own enclave
// and read a node's sealed secrets" has an answer that should be demonstrated on hardware rather
// than argued from docs.  This binary is that demonstration: a completely different MRENCLAVE,
// signed with the same key at the same productID, asking SGX for the same product key.
//
// IT PRINTS NOTHING SECRET.  Success is reported as field PRESENCE and BYTE LENGTH only -- never a
// key, a share, or a secret.  That is the whole proof; dumping plaintext would only copy secrets
// somewhere new.  It also mounts the host read-only and never writes.
//
// BUILD AND RUN, on the node, on the CPU that sealed the file:
//
//	cd cmd/sealprobe
//	ego-go build -o sealprobe .
//	ego sign enclave.json
//	ego run sealprobe -params ~/qadena/enclave_config/enclave_params_<uid>.json
//
// On a DEBUG fleet (M1-M4) there is no SGX: run it without ego and it reports the debug case, where
// "sealing" is a plaintext prefix.
//
// EXIT CODES:  0 opened it   1 could not open it   2 usage/IO error
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/syndtr/goleveldb/leveldb"
	leveldbopt "github.com/syndtr/goleveldb/leveldb/opt"
	leveldbutil "github.com/syndtr/goleveldb/leveldb/util"
)

// report prints which fields were recovered, and how big they are.  Never their contents.
func report(section string, raw json.RawMessage) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		fmt.Printf("  %-22s (not an object: %v)\n", section, err)
		return
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	fmt.Printf("  %s:\n", section)
	for _, n := range names {
		v := fields[n]
		// Length of the ENCODED value, and whether it is a non-empty/non-zero one.  Both are
		// structural facts; neither discloses the value.
		empty := bytes.Equal(v, []byte(`""`)) || bytes.Equal(v, []byte("null")) ||
			bytes.Equal(v, []byte("0")) || bytes.Equal(v, []byte("false")) || len(v) == 0
		state := "PRESENT"
		if empty {
			state = "absent "
		}
		fmt.Printf("    %-28s %s (%d bytes encoded)\n", n, state, len(v))
	}
}

// probeStore opens an enclave LevelDB read-only and asks, of real rows: are these VALUES
// product-key sealed, and can THIS binary open them?  Counts only -- no value is ever printed.
//
// Point it at a COPY of enclave_data / enclave_secrets, not the live directory, so a running node
// is never disturbed.
// probeStore opens an enclave LevelDB read-only and asks, of real rows: are these VALUES
// product-key sealed, and can THIS binary open them?  Counts only -- no value is ever printed.
//
// Pure-Go goleveldb on purpose: the cosmos-db wrapper drags in a cgo path whose symbols ego's libc
// does not provide (ego-oesign: "symbol not found: qsort_r"), so the probe would not sign.
//
// Point it at a COPY of enclave_secrets, not the live directory, so a running node is never
// disturbed.
func probeStore(dbPath, prefix string, limit int) {
	db, err := leveldb.OpenFile(dbPath, &leveldbopt.Options{ReadOnly: true})
	if err != nil {
		fmt.Printf("  %-34s cannot open %s: %v\n", prefix, dbPath, err)
		return
	}
	defer db.Close()

	it := db.NewIterator(leveldbutil.BytesPrefix([]byte(prefix)), nil)
	defer it.Release()

	var rows, opened, unsealed, failed int
	for it.Next() && rows < limit {
		rows++
		v := it.Value()
		if _, uerr := ecrypto.Unseal(v, nil); uerr == nil {
			opened++
			continue
		}
		// Not openable by us.  Is it simply not sealed at all?  A protobuf row that parses as
		// readable bytes is the unsealed case -- the owners table is written that way.
		if len(v) > 0 && (json.Valid(v) || bytes.ContainsRune(v, '{') || isMostlyPrintable(v)) {
			unsealed++
		} else {
			failed++
		}
	}
	verdict := "no rows found"
	if rows > 0 {
		verdict = fmt.Sprintf("%2d row(s): %2d OPENED by this binary, %2d unsealed, %2d sealed-but-not-openable",
			rows, opened, unsealed, failed)
	}
	fmt.Printf("  %-34s %s\n", prefix, verdict)
}

// isMostlyPrintable is a rough "this is not ciphertext" test for the control rows.
func isMostlyPrintable(b []byte) bool {
	n := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			n++
		}
	}
	return n*2 > len(b)
}

func prefixEnd(p []byte) []byte {
	end := make([]byte, len(p))
	copy(end, p)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil
}

func main() {
	params := flag.String("params", "", "path to enclave_params_<uid>.json (required unless -store-only)")
	secretsDir := flag.String("enclave-secrets", "", "path to a COPY of enclave_secrets/secrets.db -- probe its sealed VALUES")
	storeOnly := flag.Bool("store-only", false, "skip the params file; probe stores only")
	flag.Parse()

	if *secretsDir != "" {
		fmt.Println("sealprobe: probing STORE values (counts only, nothing printed)")
		fmt.Printf("enclave_secrets (%s):\n", *secretsDir)
		probeStore(*secretsDir, "Enclave/SSIntervalShares/value/", 50)
		probeStore(*secretsDir, "Enclave/SSIntervalPrivK/value/", 50)
		probeStore(*secretsDir, "Enclave/SSIntervalOwners/value/", 50)
		fmt.Println("  NOTE: enclave_data is IAVL-framed, so raw rows there are tree nodes rather than")
		fmt.Println("        logical values; its sealed values come from the same MustSeal call path.")
		fmt.Println()
	}

	if *storeOnly {
		return
	}

	if *params == "" {
		fmt.Fprintln(os.Stderr, "sealprobe: -params <path to enclave_params_<uid>.json> is required")
		os.Exit(2)
	}

	sealed, err := os.ReadFile(*params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sealprobe: cannot read %s: %v\n", *params, err)
		os.Exit(2)
	}
	fmt.Printf("sealprobe: %s (%d bytes sealed)\n", *params, len(sealed))

	// 1. THE REAL QUESTION: ask SGX for the product key.  Works only inside an enclave; outside one
	//    ego cannot derive any key and this fails for a reason that says nothing about the node.
	plain, err := ecrypto.Unseal(sealed, nil)
	mode := "REAL SGX product key (MRSIGNER + productID)"

	if err != nil {
		// 2. Not an enclave, or a different signer.  Fall back to the DEBUG case, where the enclave
		//    writes a plaintext prefix instead of sealing -- so "opening" it is just finding the JSON.
		if i := bytes.IndexByte(sealed, '{'); i >= 0 && json.Valid(sealed[i:]) {
			plain = sealed[i:]
			mode = fmt.Sprintf("DEBUG prefix sealing (prefix %q) -- NOT a statement about real SGX", sealed[:i])
		} else {
			fmt.Printf("\nRESULT: could NOT open it (%v)\n", err)
			fmt.Println("  On real SGX this is expected unless this binary is ego-signed with the node's")
			fmt.Println("  signing key at the same productID, and is running on the CPU that sealed the file.")
			os.Exit(1)
		}
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(plain, &top); err != nil {
		fmt.Fprintf(os.Stderr, "sealprobe: opened it, but the bytes are not params JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("mode: %s\n\nOPENED the sealed params -- redacted inventory of what that exposed:\n", mode)
	names := make([]string, 0, len(top))
	for k := range top {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		report(n, top[n])
	}
	fmt.Println("\n  (no value above is printed -- presence and length are the whole proof)")
	fmt.Println("\nRESULT: this binary opened the node's sealed params.")
	fmt.Println("  It is a different MRENCLAVE from qadenad_enclave; only the signing key and")
	fmt.Println("  productID match.  That is what product-key sealing grants.")
}
