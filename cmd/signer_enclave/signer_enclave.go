package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	tmcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/protoio"
	p2pconn "github.com/cometbft/cometbft/p2p/conn"
	"github.com/cometbft/cometbft/privval"
	cryptoproto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	typesproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
)

// priv_validator_key.json structure
type PrivValidatorKey struct {
	Address string `json:"address"`
	PubKey  struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"pub_key"`
	PrivKey struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"priv_key"`
}

// signer state file (double-sign protection)

//go:embed test_unique_id.txt
var uniqueID string

//go:embed test_signer_id.txt
var signerID string

//go:embed version.txt
var version string

var (

	// Enclave variables (similar to enclave.go)
	realEnclave = false
	debug       = false
)

// Web server handlers
func pingHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
		"version":   version,
		"signer_id": signerID,
		"unique_id": uniqueID,
		"mode": func() string {
			if realEnclave {
				return "real_enclave"
			}
			return "simulation"
		}(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	if debug {
		log.Printf("Ping request from %s", r.RemoteAddr)
	}
}

func startWebServer(port string) {
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/health", pingHandler) // Alias for ping

	log.Printf("Starting web server on port %s", port)
	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Printf("Web server error: %v", err)
	}
}

// sealValidatorKey seals the validator key with the SGX UNIQUE key (MRENCLAVE), not the product
// key.  Under the product key any binary signed with the repo's private.pem could open it -- the
// same exposure cmd/sealprobe demonstrated against the chain enclave's params on real hardware.
//
// BE HONEST ABOUT WHAT THIS BUYS TODAY: very little, because the PLAINTEXT key is still sitting at
// config/priv_validator_key.json and is never deleted.  Anyone who can read the sealed file can
// read the plaintext beside it.  Unique-sealing only becomes a real gain once that plaintext is
// gone, which needs either a signer handover (there is none -- the signer has no params, no
// trusted set and no chain access, so nothing to anchor one against) or a documented
// offline-backup-and-restore policy.  Keeping the plaintext is what makes loadKey's fallback below
// possible, and that fallback is what stops a rebuilt signer from stranding a validator.
func sealValidatorKey(b []byte) (ret []byte, err error) {
	if realEnclave {
		ret, err = ecrypto.SealWithUniqueKey(b, nil)
		if err != nil {
			log.Printf("sealing error: %v", err)
			return
		}
	} else {
		// Debug builds have no SGX: mirror the real policy by tagging with the MEASUREMENT, so a
		// rebuild that changes uniqueID exercises the same fall-back-to-plaintext path it would on
		// hardware.
		ret = append([]byte(uniqueID), b...)
		err = nil
	}
	return
}

func unseal(b []byte) (ret []byte, err error) {
	if realEnclave {
		ret, err = ecrypto.Unseal(b, nil)
		if err != nil {
			log.Printf("unsealing error: %v", err)
			return
		}
	} else {
		if bytes.HasPrefix(b, []byte(uniqueID)) {
			err = nil
			ret = b[len(uniqueID):]
		} else if bytes.HasPrefix(b, []byte(signerID)) {
			err = nil
			ret = b[len(signerID):]
		} else {
			err = errors.New("couldn't unseal, unrecognized prefix")
		}
	}
	return
}

// load secret connection key or generate new one
func loadOrGenerateSecretKey(path string) ed25519.PrivKey {
	data, err := ioutil.ReadFile(path)
	if err == nil && len(data) == 64 { // ed25519 private key is 64 bytes
		return ed25519.PrivKey(data)
	}

	// Generate new key and save it
	key := ed25519.GenPrivKey()
	_ = ioutil.WriteFile(path, key[:], 0600)
	if debug {
		log.Printf("Generated new secret connection key: %s", path)
	}
	return key
}

// loadKey returns the validator's consensus key, preferring the sealed copy and falling back to
// the plaintext one.
//
// THE RULE: the signer must work whenever the unencrypted key is present.
//
// The sealed copy at enclave_config/priv_validator_key.json is bound to one MEASUREMENT (it is
// sealed with the SGX unique key) and to one CPU.  So it is UNREADABLE in two ordinary situations:
// the first start of any rebuilt signer, and a node whose VM moved to another host.  Treating that
// as fatal -- which this used to do -- stops the signer, and a validator that cannot load its key
// cannot sign, so the node halts.  config/priv_validator_key.json is the authority and is never
// deleted, so the right answer is to re-seal from it and carry on.
//
// Order:
//  1. sealed file opens            -> use it
//  2. sealed file will not open    -> say so loudly, fall through
//  3. plaintext present            -> parse, seal for THIS measurement, replace the stale sealed
//     copy, use it
//  4. neither                      -> fail, naming both paths and the remedy
func loadKey(homePath string) (ed25519.PrivKey, tmcrypto.PubKey, error) {
	unencryptedPath := filepath.Join(homePath, "config", "priv_validator_key.json")
	encryptedPath := filepath.Join(homePath, "enclave_config", "priv_validator_key.json")

	// fromJSON turns either file's contents into a usable key pair.
	fromJSON := func(raw []byte) (ed25519.PrivKey, tmcrypto.PubKey, error) {
		var key PrivValidatorKey
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal key json: %w", err)
		}
		privBytes, err := base64.StdEncoding.DecodeString(key.PrivKey.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode privkey: %w", err)
		}
		var priv ed25519.PrivKey = privBytes
		return priv, priv.PubKey(), nil
	}

	// 1 and 2.
	if sealed, err := ioutil.ReadFile(encryptedPath); err == nil {
		plain, uerr := unseal(sealed)
		if uerr == nil {
			priv, pub, perr := fromJSON(plain)
			if perr != nil {
				return nil, nil, perr
			}
			if debug {
				log.Printf("Loaded the sealed validator key from %s", encryptedPath)
			}
			return priv, pub, nil
		}
		log.Printf("NOTE: %s exists but this build cannot open it (%v)", encryptedPath, uerr)
		log.Printf("      falling back to the plaintext key and re-sealing.  Expected after an enclave")
		log.Printf("      rebuild or a move to another CPU -- the seal is bound to both.")
	}

	// 3.
	raw, err := ioutil.ReadFile(unencryptedPath)
	if err != nil {
		// 4.  Name both paths: an operator seeing only one of them cannot tell which to restore.
		return nil, nil, fmt.Errorf("no validator key this signer can use: %s could not be opened and %s is absent (%w).  "+
			"Restore the plaintext key from your offline backup into config/ and start again", encryptedPath, unencryptedPath, err)
	}

	priv, pub, perr := fromJSON(raw)
	if perr != nil {
		return nil, nil, perr
	}

	// WHICH KEY DID WE JUST ADOPT?  This is the only line that would reveal an operator having
	// replaced the plaintext with a DIFFERENT validator key.  That failure is availability -- the
	// chain rejects an unknown validator and the node gets jailed -- not equivocation, but it is
	// worth being able to see at a glance.
	log.Printf("Loaded the plaintext validator key from %s, address: %X", unencryptedPath, pub.Address())

	// Re-seal for THIS measurement, replacing any stale copy.
	sealed, serr := sealValidatorKey(raw)
	if serr != nil {
		// Not fatal: the key is loaded and the node can sign.  Only the at-rest copy is missing,
		// and the next start will try again.
		log.Printf("Warning: failed to seal the validator key: %v", serr)
		return priv, pub, nil
	}
	enclaveConfigDir := filepath.Join(homePath, "enclave_config")
	if err := os.MkdirAll(enclaveConfigDir, 0755); err != nil {
		log.Printf("Warning: failed to create %s: %v", enclaveConfigDir, err)
		return priv, pub, nil
	}
	// 0600, not 0644: it is a validator key, sealed or not.
	if err := os.WriteFile(encryptedPath, sealed, 0600); err != nil {
		log.Printf("Warning: failed to save the sealed validator key: %v", err)
	} else {
		log.Printf("Sealed the validator key for this measurement at %s", encryptedPath)
	}
	return priv, pub, nil
}

func main() {
	// Command line arguments
	homePath := flag.String("home", ".", "Path to the home directory for keys and state files")
	remoteAddr := flag.String("addr", "127.0.0.1:26659", "Remote validator address to connect to")
	webPort := flag.String("web-port", "26661", "Web server port for ping/health endpoints")
	realEnclaveFlag := flag.Bool("real-enclave", false, "Run in real enclave mode (SGX)")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	showVersion := flag.Bool("version", false, "Show version and exit")
	querySignerID := flag.Bool("query-signer-id", false, "Query signer ID and exit")
	queryUniqueID := flag.Bool("query-unique-id", false, "Query unique ID and exit")
	flag.Parse()

	// Set global debug flag
	debug = *debugFlag

	// Set global realEnclave flag
	realEnclave = *realEnclaveFlag

	// Handle GetSelfReport for real enclave mode
	if realEnclave {
		selfReport, err := enclave.GetSelfReport()
		if err != nil {
			log.Fatalf("couldn't get self report: %v", err)
		}
		uniqueID = hex.EncodeToString(selfReport.UniqueID)
		signerID = hex.EncodeToString(selfReport.SignerID)
	}

	// Handle query flags
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *querySignerID {
		fmt.Println(signerID)
		os.Exit(0)
	}

	if *queryUniqueID {
		fmt.Println(uniqueID)
		os.Exit(0)
	}

	if realEnclave {
		log.Printf("Running in real enclave mode (SGX) - UniqueID: %s, SignerID: %s", uniqueID[:16]+"...", signerID[:16]+"...")
	} else {
		log.Printf("Running in simulation mode - UniqueID: %s, SignerID: %s", uniqueID, signerID)
	}
	log.Printf("Signer version: %s", version)

	// Construct file paths relative to home directory
	secretKeyPath := filepath.Join(*homePath, "enclave_data", "secret_connection.key")
	stateFilePath := filepath.Join(*homePath, "enclave_data", "signer_state.json")

	priv, pub, err := loadKey(*homePath)
	if err != nil {
		log.Fatalf("Error loading validator key: %v", err)
	}
	pv, note, err := loadPrivValidator(priv, stateFilePath)
	if err != nil {
		log.Fatalf("double-sign protection: %v", err)
	}
	log.Printf("double-sign protection: %s", note)
	log.Printf("Loaded validator key, address: %X\n", pub.Address())

	// Load or generate secret connection key for P2P encryption
	secretConnKey := loadOrGenerateSecretKey(secretKeyPath)
	if debug {
		log.Printf("Secret connection key from %s, address: %X\n", secretKeyPath, secretConnKey.PubKey().Address())
	}

	// Start web server in background
	go startWebServer(*webPort)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		log.Printf("Received SIGINT, exiting with code 20")
		os.Exit(20)
	}()

	// TCP dialer - connect to remote validator with retry
	log.Printf("Dialing remote validator at %s", *remoteAddr)

	maxRetries := 60 // 1 minute with 1 second intervals

	// RECONNECT, DO NOT EXIT.  The retry loop below only ever covered the FIRST dial: once
	// connected, handleConnection served until the socket closed and then main returned, exiting
	// 0.  A closed socket is not "work finished" -- CometBFT's SignerListener drops the connection
	// on a PING TIMEOUT and immediately loops back to accept a new one, so the listener is sitting
	// there waiting while the only process that could answer has just left.
	//
	// Measured on pioneer2, 2026-08-26 11:45: a 1481ms consensus step, then "SignerListener: Ping
	// timeout", then "signer_enclave process exited unexpectedly (code 0)", then the node halting
	// itself because it will not sign without a signer.  A transient stall cost a validator for
	// over an hour.  The enclave was healthy throughout -- 32MB heap, 24 goroutines.
	//
	// THIS IS NOT THE RESPAWN LOOP 96313d25 REMOVED, and the distinction is the point.  That
	// policy is about a PARENT not resurrecting a dead child: "a spawned enclave that exits takes
	// the node down with a named cause ... the loop only ever saved an idle crash, at the price of
	// hiding every crash it recovered".  Nothing here is dead.  This process is alive and holds
	// its key; it is re-establishing its own connection, which is the ordinary contract for a
	// CometBFT remote signer.  A signer that genuinely cannot reach the node still gives up after
	// maxRetries and exits non-zero, so a real failure is still loud, and SIGINT still exits 20.
	for {
		if !dialAndServe(*remoteAddr, secretConnKey, pv, pub, maxRetries) {
			return
		}
		log.Printf("connection to %s closed -- redialing (the node's listener is already waiting for us)", *remoteAddr)
	}
}

// dialAndServe connects once and serves until the connection closes.  Returns true if the caller
// should redial, false if it should stop trying.
func dialAndServe(remoteAddr string, secretConnKey ed25519.PrivKey, pv *privval.FilePV, pub tmcrypto.PubKey, maxRetries int) bool {
	var conn net.Conn

	for attempt := 1; attempt <= maxRetries; attempt++ {
		var err error
		conn, err = net.Dial("tcp", remoteAddr)
		if err == nil {
			fmt.Printf("Connected to remote validator at %s (attempt %d)\n", conn.RemoteAddr(), attempt)

			// Establish secret connection (encrypted P2P connection)
			secretConn, err := p2pconn.MakeSecretConnection(conn, secretConnKey)
			if err != nil {
				log.Printf("Failed to establish secret connection: %v", err)
				conn.Close()
				if attempt == maxRetries {
					log.Fatalf("Failed to establish secret connection after %d attempts", maxRetries)
				}
				time.Sleep(1 * time.Second)
				continue
			}

			log.Printf("Established secret connection with %X", secretConn.RemotePubKey().Address())
			handleConnection(secretConn, pv, pub)
			return true
		}

		if attempt == maxRetries {
			log.Fatalf("Failed to dial remote validator after %d attempts: %v", maxRetries, err)
		}

		if debug {
			log.Printf("Connection attempt %d failed: %v. Retrying in 1 second...", attempt, err)
		}
		time.Sleep(1 * time.Second)
	}
	// Unreachable: the loop above ends only via log.Fatalf on the final attempt.  Returning false
	// rather than true keeps the caller honest if that ever changes -- a dial loop that has given
	// up must not be re-entered forever.
	return false
}

func handleConnection(conn net.Conn, pv *privval.FilePV, pub tmcrypto.PubKey) {
	defer func() {
		log.Printf("Closing connection to %s", conn.RemoteAddr())
		conn.Close()
	}()

	if debug {
		log.Printf("Handling connection from %s", conn.RemoteAddr())
	}
	const maxRemoteSignerMsgSize = 1024 * 10
	protoReader := protoio.NewDelimitedReader(conn, maxRemoteSignerMsgSize)

	for {
		var msg cmproto.Message
		if _, err := protoReader.ReadMsg(&msg); err != nil {
			log.Println("Read message error:", err)
			return
		}

		switch sum := msg.Sum.(type) {
		case *cmproto.Message_PubKeyRequest:
			chainID := sum.PubKeyRequest.ChainId
			if debug {
				log.Printf("PubKeyRequest for chain: %s", chainID)
			}
			resp := &cmproto.Message{
				Sum: &cmproto.Message_PubKeyResponse{
					PubKeyResponse: &cmproto.PubKeyResponse{
						PubKey: cryptoproto.PublicKey{
							Sum: &cryptoproto.PublicKey_Ed25519{Ed25519: pub.Bytes()},
						},
					},
				},
			}
			sendMsg(conn, resp)

		case *cmproto.Message_SignVoteRequest:
			vote := sum.SignVoteRequest.Vote
			chainID := sum.SignVoteRequest.ChainId
			if debug {
				log.Println("SignVoteRequest ", vote)
			}
			// Double-sign protection and vote extensions both live in signVote (signer_state.go):
			// CometBFT's own FilePV rules, state on disk before the signature leaves.
			var resp *cmproto.Message
			if err := signVote(pv, chainID, vote); err != nil {
				log.Printf("REFUSING to sign vote H/R/type %d/%d/%v: %v", vote.Height, vote.Round, vote.Type, err)
				resp = &cmproto.Message{Sum: &cmproto.Message_SignedVoteResponse{SignedVoteResponse: &cmproto.SignedVoteResponse{
					Vote: typesproto.Vote{}, Error: &cmproto.RemoteSignerError{Code: 0, Description: err.Error()},
				}}}
			} else {
				vote.ValidatorAddress = pub.Address()
				resp = &cmproto.Message{Sum: &cmproto.Message_SignedVoteResponse{SignedVoteResponse: &cmproto.SignedVoteResponse{Vote: *vote}}}
			}
			sendMsg(conn, resp)

		case *cmproto.Message_SignProposalRequest:
			prop := sum.SignProposalRequest.Proposal
			chainID := sum.SignProposalRequest.ChainId
			if debug {
				log.Println("SignProposalRequest ", prop)
			}
			var resp *cmproto.Message
			if err := signProposal(pv, chainID, prop); err != nil {
				log.Printf("REFUSING to sign proposal H/R %d/%d: %v", prop.Height, prop.Round, err)
				resp = &cmproto.Message{Sum: &cmproto.Message_SignedProposalResponse{SignedProposalResponse: &cmproto.SignedProposalResponse{
					Proposal: typesproto.Proposal{}, Error: &cmproto.RemoteSignerError{Code: 0, Description: err.Error()},
				}}}
			} else {
				resp = &cmproto.Message{Sum: &cmproto.Message_SignedProposalResponse{SignedProposalResponse: &cmproto.SignedProposalResponse{Proposal: *prop}}}
			}
			sendMsg(conn, resp)

		case *cmproto.Message_PingRequest:
			if debug {
				log.Printf("PingRequest from %s", conn.RemoteAddr())
			}
			resp := &cmproto.Message{
				Sum: &cmproto.Message_PingResponse{PingResponse: &cmproto.PingResponse{}},
			}
			sendMsg(conn, resp)
			if debug {
				log.Printf("PingResponse sent to %s", conn.RemoteAddr())
			}
		}
	}
}

func sendMsg(conn net.Conn, msg *cmproto.Message) {
	protoWriter := protoio.NewDelimitedWriter(conn)
	if _, err := protoWriter.WriteMsg(msg); err != nil {
		log.Printf("Write message error to %s: %v", conn.RemoteAddr(), err)
		return
	}
}
