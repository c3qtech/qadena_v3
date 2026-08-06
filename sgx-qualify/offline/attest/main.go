// attest -- runs INSIDE an enclave and prints a quote as text, for machines with no network path
// between them.
//
// FRESHNESS IS THE WHOLE DIFFICULTY OFFLINE.  A quote is just bytes; nothing about it says when it
// was produced.  Copied without a challenge, an old quote from a machine that has since been
// decommissioned, downgraded or compromised verifies exactly as well as one made a second ago.
//
// So the verifier issues a nonce first and this binds it into the report:
//
//   1. verifier:  ./verify --new-nonce          -> prints a random nonce
//   2. copy the nonce to the enclave machine
//   3. enclave:   ego run ./attest --nonce <n>  -> prints a quote blob
//   4. copy the blob back
//   5. verifier:  ./verify --nonce <n> --quote-file blob.txt
//
// The nonce may be omitted, and then this prints a quote bound to nothing.  That still exercises
// quote generation and verification, which is often all you want when qualifying hardware -- but it
// proves nothing about freshness, and --require-nonce on the verifier refuses it for that reason.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/edgelesssys/ego/enclave"
)

func main() {
	nonce := flag.String("nonce", "", "hex nonce from the verifier; binds this quote to this request")
	width := flag.Int("width", 100, "wrap the blob at this column for copy/paste")
	flag.Parse()

	var reportData []byte
	if *nonce != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(*nonce))
		if err != nil {
			fmt.Fprintf(os.Stderr, "nonce is not hex: %v\n", err)
			os.Exit(2)
		}
		// Hashed rather than used raw: report data is a fixed 64 bytes, and hashing accepts a nonce
		// of any length while making the binding unambiguous.
		sum := sha256.Sum256(raw)
		reportData = sum[:]
	}

	report, err := enclave.GetRemoteReport(reportData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetRemoteReport failed: %v\n\n"+
			"This is quote GENERATION, so the problem is on THIS machine:\n"+
			"  - is libsgx-dcap-default-qpl installed?\n"+
			"  - can this user open /dev/sgx_provision?  That is group sgx_prv, which is NOT\n"+
			"    the same group as /dev/sgx_enclave -- being in one and not the other lets an\n"+
			"    enclave run while quotes cannot be produced.\n", err)
		os.Exit(1)
	}

	enc := base64.StdEncoding.EncodeToString(report)
	fmt.Fprintf(os.Stderr, "quote: %d bytes", len(report))
	if *nonce != "" {
		fmt.Fprintf(os.Stderr, ", bound to nonce %s", *nonce)
	} else {
		fmt.Fprintf(os.Stderr, ", NOT bound to a nonce (no freshness guarantee)")
	}
	fmt.Fprintln(os.Stderr, "\n--- copy everything between the markers ---")

	fmt.Println("-----BEGIN SGX QUOTE-----")
	for i := 0; i < len(enc); i += *width {
		end := i + *width
		if end > len(enc) {
			end = len(enc)
		}
		fmt.Println(enc[i:end])
	}
	fmt.Println("-----END SGX QUOTE-----")
}
