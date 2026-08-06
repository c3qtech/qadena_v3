// Minimal EGo remote attestation client.  Runs OUTSIDE any enclave, on a DIFFERENT machine.
//
// Verification here is independent of the server: separate collateral, separate libraries, separate
// host.  That separation is the whole reason this tool exists -- a machine can generate quotes it
// cannot itself meaningfully verify, and vice versa, and neither shows up in a single-box test.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/edgelesssys/ego/eclient"
)

type bundle struct {
	Cert   []byte `json:"cert"`
	Report []byte `json:"report"`
}

func main() {
	host := flag.String("host", "", "server address (ip or hostname)")
	attestPort := flag.String("attest-port", "8080", "plain-HTTP port serving the bundle")
	tlsPort := flag.String("tls-port", "8443", "TLS port of the attested service")
	wantUnique := flag.String("unique-id", "", "required MRENCLAVE (hex); printed if omitted")
	wantSigner := flag.String("signer-id", "", "required MRSIGNER (hex); printed if omitted")
	wantProduct := flag.Int("product-id", -1, "required product id; ignored if negative")
	minSecurity := flag.Int("min-security-version", -1, "minimum security version; ignored if negative")
	requireProd := flag.Bool("require-production", false, "fail if the enclave was signed in debug mode")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "usage: client --host <server-ip> [--unique-id ...] [--require-production]")
		os.Exit(2)
	}

	failed := false
	fail := func(format string, a ...any) {
		fmt.Printf("  FAIL  "+format+"\n", a...)
		failed = true
	}
	ok := func(format string, a ...any) { fmt.Printf("  ok    "+format+"\n", a...) }

	fmt.Printf("qualifying %s\n\n", *host)

	// 1 ------------------------------------------------------------------ fetch
	fmt.Println("1. fetch the attestation bundle (plain HTTP -- nothing is trusted yet)")
	b, err := fetchBundle(fmt.Sprintf("http://%s:%s/attest", *host, *attestPort))
	if err != nil {
		fmt.Printf("  FAIL  could not fetch the bundle: %v\n", err)
		os.Exit(1)
	}
	ok("bundle: %d byte certificate, %d byte quote", len(b.Cert), len(b.Report))

	// 2 ----------------------------------------------------------------- verify
	fmt.Println("\n2. verify the quote (independently, on this machine)")
	report, err := eclient.VerifyRemoteReport(b.Report)
	if err != nil {
		// A TCB-status error means something quite different from a failure to verify -- the quote
		// is genuine and the PLATFORM is out of date -- but eclient reports it through the same
		// return, so the message says both rather than guessing.
		fmt.Printf("  FAIL  verification failed: %v\n", err)
		fmt.Println("        this is quote VERIFICATION, so the problem is on THIS machine:")
		fmt.Println("        usually /etc/sgx_default_qcnl.conf pointing at an unreachable PCCS.")
		os.Exit(1)
	}
	ok("quote verified by the DCAP libraries on this host")

	// 3 ---------------------------------------------------------------- binding
	fmt.Println("\n3. the quote is bound to THIS certificate")
	hash := sha256.Sum256(b.Cert)
	if len(report.Data) < len(hash) || !equal(report.Data[:len(hash)], hash[:]) {
		fail("report data does not match sha256(cert); the quote belongs to a different enclave")
		fmt.Printf("        cert sha256: %x\n", hash)
		if len(report.Data) >= len(hash) {
			fmt.Printf("        report data: %x\n", report.Data[:len(hash)])
		}
	} else {
		ok("report data == sha256(cert) == %s", hex.EncodeToString(hash[:])[:32]+"...")
	}

	// 4 ------------------------------------------------------------- identities
	fmt.Println("\n4. enclave identity")
	fmt.Printf("        MRENCLAVE (unique id): %s\n", hex.EncodeToString(report.UniqueID))
	fmt.Printf("        MRSIGNER  (signer id): %s\n", hex.EncodeToString(report.SignerID))
	fmt.Printf("        product id: %d   security version: %d   debug: %v\n",
		productID(report.ProductID), report.SecurityVersion, report.Debug)
	fmt.Printf("        TCB status: %v\n", report.TCBStatus)

	if *wantUnique != "" && !strings.EqualFold(hex.EncodeToString(report.UniqueID), *wantUnique) {
		fail("MRENCLAVE is not the expected %s", *wantUnique)
	} else if *wantUnique != "" {
		ok("MRENCLAVE matches")
	}
	if *wantSigner != "" && !strings.EqualFold(hex.EncodeToString(report.SignerID), *wantSigner) {
		fail("MRSIGNER is not the expected %s", *wantSigner)
	} else if *wantSigner != "" {
		ok("MRSIGNER matches")
	}
	if *wantProduct >= 0 {
		if productID(report.ProductID) != uint64(*wantProduct) {
			fail("product id is not %d", *wantProduct)
		} else {
			ok("product id matches")
		}
	}
	if *minSecurity >= 0 {
		if report.SecurityVersion < uint(*minSecurity) {
			fail("security version %d is below the required %d", report.SecurityVersion, *minSecurity)
		} else {
			ok("security version is at least %d", *minSecurity)
		}
	}
	// A debug enclave produces a perfectly valid quote whose memory is NOT confidential, so this is
	// the difference between a working attestation and a meaningful one.
	if *requireProd {
		if report.Debug {
			fail("the enclave is signed in DEBUG mode; its memory is not confidential")
		} else {
			ok("enclave is production-signed (debug flag clear)")
		}
	}

	// 5 -------------------------------------------------------------- the channel
	fmt.Println("\n5. the TLS channel terminates in the attested enclave")
	body, err := getPinned(fmt.Sprintf("https://%s:%s/secret", *host, *tlsPort), b.Cert)
	if err != nil {
		fail("could not reach the attested service: %v", err)
	} else {
		ok("response: %s", strings.TrimSpace(string(body)))
	}

	fmt.Println()
	if failed {
		fmt.Println("QUALIFICATION FAILED")
		os.Exit(1)
	}
	fmt.Println("QUALIFICATION PASSED")
}

// productID renders the 16-byte ISVPRODID field as the number you put in enclave.json.  Printed raw
// it comes out as "[1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]", which is accurate and unreadable.
func productID(b []byte) uint64 {
	var v uint64
	for i := 0; i < len(b) && i < 8; i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

func fetchBundle(url string) (*bundle, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	if len(b.Cert) == 0 || len(b.Report) == 0 {
		return nil, errors.New("bundle is missing the certificate or the quote")
	}
	return &b, nil
}

// getPinned trusts the attested certificate and NOTHING ELSE.  InsecureSkipVerify disables the PKI
// path deliberately -- there is no CA in this design and there should not be, because the quote is
// what establishes trust.  VerifyPeerCertificate then does the only check that matters: the peer
// must present the exact certificate the quote vouched for.
func getPinned(url string, certDER []byte) ([]byte, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || !equal(rawCerts[0], certDER) {
				return errors.New("peer certificate is not the attested one")
			}
			return nil
		},
	}
	c := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
