// Minimal EGo remote attestation server.  Runs INSIDE an enclave.
//
// It creates a TLS key pair in the enclave, binds the certificate into a hardware-signed quote, and
// serves both.  Nothing here is Qadena-specific; the whole point is to exercise the platform.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/edgelesssys/ego/enclave"
)

// bundle is what a client needs before it can trust anything: the certificate it will pin, and the
// quote that vouches for it.
type bundle struct {
	Cert   []byte `json:"cert"`   // DER
	Report []byte `json:"report"` // DCAP quote
}

func main() {
	certDER, priv := createCertificate()

	// THE BINDING THAT MAKES THIS MEANINGFUL.  reportData is covered by the hardware signature, so a
	// verifier that checks sha256(cert) == report.Data learns that this key belongs to this enclave.
	// Without it the quote would prove only that SOME enclave exists somewhere, and anyone could
	// replay a valid quote in front of their own TLS endpoint.
	hash := sha256.Sum256(certDER)
	report, err := enclave.GetRemoteReport(hash[:])
	if err != nil {
		log.Fatalf("GetRemoteReport failed: %v\n"+
			"this is quote GENERATION, so the problem is on this machine: check that\n"+
			"libsgx-dcap-default-qpl is installed and that this user can open /dev/sgx_provision\n"+
			"(group sgx_prv, which is NOT the same group as /dev/sgx_enclave)", err)
	}
	log.Printf("quote generated: %d bytes, bound to cert sha256 %x", len(report), hash)

	body, err := json.Marshal(bundle{Cert: certDER, Report: report})
	if err != nil {
		log.Fatalf("marshal bundle: %v", err)
	}

	// DELIBERATELY PLAIN HTTP.  The client cannot trust our TLS until it has verified the quote, so
	// the bundle has to be fetchable before any trust exists.  Serving it over the very TLS it is
	// meant to justify would be circular.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		})
		log.Println("attestation bundle: http://0.0.0.0:8080/attest")
		log.Fatal(http.ListenAndServe(":8080", mux))
	}()

	// The attested service.  Reaching this at all proves the channel terminates inside the enclave
	// whose measurements the client just checked.
	mux := http.NewServeMux()
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this response came from inside the enclave\n"))
	})
	srv := &http.Server{
		Addr:    ":8443",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: priv}},
			MinVersion:   tls.VersionTLS12,
		},
	}
	log.Println("attested service: https://0.0.0.0:8443/secret")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// createCertificate makes a self-signed certificate whose private key never leaves the enclave.
// Self-signed is correct here rather than a shortcut: the client pins this exact certificate on the
// strength of the quote, so a CA would add nothing.
func createCertificate() ([]byte, crypto.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sgx-qualify enclave"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}
	return der, priv
}
