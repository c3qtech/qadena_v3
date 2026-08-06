// verify -- runs OUTSIDE any enclave, on the other machine, and checks a pasted quote.
//
// See offline/attest for why the nonce matters.  In short: a quote carries no timestamp, so without
// a challenge this tells you a machine COULD once produce a valid quote, not that it can now.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/edgelesssys/ego/eclient"
)

func main() {
	newNonce := flag.Bool("new-nonce", false, "print a fresh nonce and exit")
	nonce := flag.String("nonce", "", "the nonce issued for this quote; required unless --allow-stale")
	allowStale := flag.Bool("allow-stale", false, "accept a quote not bound to a nonce (no freshness)")
	quoteFile := flag.String("quote-file", "", "file holding the pasted quote; default stdin")
	wantUnique := flag.String("unique-id", "", "required MRENCLAVE (hex)")
	wantSigner := flag.String("signer-id", "", "required MRSIGNER (hex)")
	requireProd := flag.Bool("require-production", false, "fail if the enclave was signed in debug mode")
	flag.Parse()

	if *newNonce {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintf(os.Stderr, "could not generate a nonce: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(b))
		return
	}

	if *nonce == "" && !*allowStale {
		fmt.Fprintln(os.Stderr,
			"refusing to verify without a nonce.\n\n"+
				"A quote carries no timestamp, so an unbound one proves only that this machine could\n"+
				"produce a valid quote at SOME point -- possibly before it was downgraded or\n"+
				"decommissioned.  Issue one with --new-nonce, or pass --allow-stale if you are\n"+
				"qualifying hardware and freshness genuinely does not matter.")
		os.Exit(2)
	}

	raw, err := readQuote(*quoteFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read the quote: %v\n", err)
		os.Exit(1)
	}

	failed := false
	fail := func(format string, a ...any) {
		fmt.Printf("  FAIL  "+format+"\n", a...)
		failed = true
	}
	ok := func(format string, a ...any) { fmt.Printf("  ok    "+format+"\n", a...) }

	fmt.Printf("verifying a %d byte quote\n\n", len(raw))

	fmt.Println("1. verify the quote (independently, on this machine)")
	report, err := eclient.VerifyRemoteReport(raw)
	if err != nil {
		fmt.Printf("  FAIL  verification failed: %v\n\n", err)
		fmt.Println("        This is quote VERIFICATION, so the problem is on THIS machine --")
		fmt.Println("        usually /etc/sgx_default_qcnl.conf pointing at an unreachable PCCS.")
		fmt.Println("        A TCB-status error means the opposite: the quote is genuine and the")
		fmt.Println("        REMOTE platform needs microcode or PSW updates.")
		os.Exit(1)
	}
	ok("quote verified by the DCAP libraries on this host")

	fmt.Println("\n2. freshness")
	if *nonce != "" {
		nb, err := hex.DecodeString(strings.TrimSpace(*nonce))
		if err != nil {
			fail("nonce is not hex: %v", err)
		} else {
			sum := sha256.Sum256(nb)
			if len(report.Data) < len(sum) || !equal(report.Data[:len(sum)], sum[:]) {
				fail("the quote is NOT bound to this nonce; it may be a replay of an older quote")
			} else {
				ok("bound to the nonce issued for this request")
			}
		}
	} else {
		fmt.Println("  warn  no nonce: this quote could have been produced at any time (--allow-stale)")
	}

	fmt.Println("\n3. enclave identity")
	fmt.Printf("        MRENCLAVE (unique id): %s\n", hex.EncodeToString(report.UniqueID))
	fmt.Printf("        MRSIGNER  (signer id): %s\n", hex.EncodeToString(report.SignerID))
	fmt.Printf("        product id: %d   security version: %d   debug: %v\n",
		report.ProductID, report.SecurityVersion, report.Debug)
	fmt.Printf("        TCB status: %v\n", report.TCBStatus)

	if *wantUnique != "" {
		if strings.EqualFold(hex.EncodeToString(report.UniqueID), *wantUnique) {
			ok("MRENCLAVE matches")
		} else {
			fail("MRENCLAVE is not the expected %s", *wantUnique)
		}
	}
	if *wantSigner != "" {
		if strings.EqualFold(hex.EncodeToString(report.SignerID), *wantSigner) {
			ok("MRSIGNER matches")
		} else {
			fail("MRSIGNER is not the expected %s", *wantSigner)
		}
	}
	if *requireProd {
		if report.Debug {
			fail("the enclave is signed in DEBUG mode; its memory is not confidential")
		} else {
			ok("enclave is production-signed (debug flag clear)")
		}
	}

	fmt.Println()
	if failed {
		fmt.Println("QUALIFICATION FAILED")
		os.Exit(1)
	}
	fmt.Println("QUALIFICATION PASSED")
}

// readQuote accepts the marker-wrapped output of attest, or bare base64, from a file or stdin --
// whichever survived being pasted through a terminal.
func readQuote(path string) ([]byte, error) {
	var r io.Reader = os.Stdin
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	var sb strings.Builder
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		sb.WriteString(line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if sb.Len() == 0 {
		return nil, fmt.Errorf("no quote data found")
	}
	return base64.StdEncoding.DecodeString(sb.String())
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
