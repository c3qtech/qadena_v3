//go:build realenclave
// +build realenclave

// this only gets built on Linux/SGX

package main

import (
	"bytes"
	//	"encoding/binary"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	//	"fmt"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/eclient"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// CLONE ALERT:  THIS IS MOSTLY A CLONE OF jar_realenclave.go

var VerifyReportSignerID []byte
var VerifyReportUniqueID []byte

func verifyReport(report attestation.Report) error {
	if !bytes.Equal(report.SignerID, VerifyReportSignerID) {
		return errors.New("invalid signer")
	}

	return nil
}

func dialRealEnclave(logger log.Logger, addr string, signerID string, uniqueID string) (*grpc.ClientConn, error) {
	c.LoggerDebug(logger, "dialRealEnclave", addr, signerID, uniqueID)

	// get signerID command line argument
	var err error
	VerifyReportSignerID, err = hex.DecodeString(signerID)
	if err != nil {
		return nil, err
	}

	if len(VerifyReportSignerID) == 0 {
		return nil, errors.New("signerID missing")
	}

	VerifyReportUniqueID, err = hex.DecodeString(uniqueID)
	if err != nil {
		return nil, err
	}

	if len(VerifyReportUniqueID) == 0 {
		return nil, errors.New("uniqueID missing")
	}

	// Create a TLS config that verifies a certificate with embedded report.
	tlsConfig := eclient.CreateAttestationClientTLSConfig(verifyReport)

	c.LoggerDebug(logger, "tlsConfig", tlsConfig)

	// Set up a connection to the server.
	cred := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(cred))

	return conn, err
}

// returns nil if valid
func clientVerifyRemoteReportRealEnclave(sdkctx sdk.Context, remoteReportBytes []byte, certifyData string) (success bool, signerID string, uniqueID string) {
	remoteReport, err := eclient.VerifyRemoteReport(remoteReportBytes)
	if err != nil {
		c.ContextError(sdkctx, "error verifying remote report", err)
		return false, "", ""
	}

	hash := sha256.Sum256([]byte(certifyData))
	if bytes.Compare(remoteReport.Data[:len(hash)], hash[:]) != 0 {
		c.ContextError(sdkctx, "mismatch hash")
		c.ContextError(sdkctx, "remoteReportData hash", hex.EncodeToString(remoteReport.Data[:len(hash)]))
		c.ContextError(sdkctx, "certifyData hash", hex.EncodeToString(hash[:]))
		return false, "", ""
	}
	c.ContextDebug(sdkctx, "hash match")

	return true, hex.EncodeToString(remoteReport.SignerID), hex.EncodeToString(remoteReport.UniqueID)
}

func init() {
	keeper.EnclaveDialEnclave = dialRealEnclave
	keeper.EnclaveClientVerifyRemoteReport = clientVerifyRemoteReportRealEnclave
}
