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
	"sync"
	"time"

	tmcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/protoio"
	p2pconn "github.com/cometbft/cometbft/p2p/conn"
	cryptoproto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	typesproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
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
type SignerState struct {
	Height int64 `json:"height"`
	Round  int32 `json:"round"`
	Step   int8  `json:"step"`
}

//go:embed test_unique_id.txt
var uniqueID string

//go:embed test_signer_id.txt
var signerID string

//go:embed version.txt
var version string

var (
	stateFile = "signer_state.json"
	stateLock sync.Mutex

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

// Encryption/decryption functions (similar to enclave.go)
func sealWithProductKey(b []byte) (ret []byte, err error) {
	if realEnclave {
		ret, err = ecrypto.SealWithProductKey(b, nil)
		if err != nil {
			log.Printf("sealing error: %v", err)
			return
		}
	} else {
		ret = append([]byte(signerID), b...)
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

// load validator key with encryption support
func loadKey(homePath string) (ed25519.PrivKey, tmcrypto.PubKey, error) {
	unencryptedPath := filepath.Join(homePath, "config", "priv_validator_key.json")
	encryptedPath := filepath.Join(homePath, "enclave_config", "priv_validator_key.json")

	if debug {
		log.Printf("Checking for encrypted key at: %s", encryptedPath)
	}

	// First try to load encrypted version
	if encryptedData, err := ioutil.ReadFile(encryptedPath); err == nil {
		if debug {
			log.Printf("Found encrypted key, attempting to decrypt")
		}

		// Decrypt the data
		decryptedData, err := unseal(encryptedData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt key file: %w", err)
		}

		// Parse the decrypted JSON
		var key PrivValidatorKey
		if err := json.Unmarshal(decryptedData, &key); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal decrypted key json: %w", err)
		}

		privBytes, err := base64.StdEncoding.DecodeString(key.PrivKey.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode privkey: %w", err)
		}

		var priv ed25519.PrivKey = privBytes
		pub := priv.PubKey()
		if debug {
			log.Printf("Successfully loaded encrypted key")
		}
		return priv, pub, nil
	}

	if debug {
		log.Printf("No encrypted key found, checking for unencrypted key at: %s", unencryptedPath)
	}

	// Try to load unencrypted version
	unencryptedData, err := ioutil.ReadFile(unencryptedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file from both %s and %s: %w", encryptedPath, unencryptedPath, err)
	}

	if debug {
		log.Printf("Found unencrypted key, loading and encrypting")
	}

	// Parse the unencrypted JSON
	var key PrivValidatorKey
	if err := json.Unmarshal(unencryptedData, &key); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal key json: %w", err)
	}

	// Create encrypted version and save it
	encryptedData, err := sealWithProductKey(unencryptedData)
	if err != nil {
		log.Printf("Warning: failed to encrypt key: %v", err)
	} else {
		// Ensure enclave_config directory exists
		enclaveConfigDir := filepath.Join(homePath, "enclave_config")
		if err := os.MkdirAll(enclaveConfigDir, 0755); err != nil {
			log.Printf("Warning: failed to create enclave_config directory: %v", err)
		} else {
			// Save encrypted version
			if err := os.WriteFile(encryptedPath, encryptedData, 0644); err != nil {
				log.Printf("Warning: failed to save encrypted key: %v", err)
			} else if debug {
				log.Printf("Successfully saved encrypted key to: %s", encryptedPath)
			}
		}
	}

	privBytes, err := base64.StdEncoding.DecodeString(key.PrivKey.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode privkey: %w", err)
	}

	var priv ed25519.PrivKey = privBytes
	pub := priv.PubKey()
	return priv, pub, nil
}

// load signer state
func loadState() SignerState {
	var st SignerState
	data, err := ioutil.ReadFile(stateFile)
	if err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

// save signer state
func saveState(st SignerState) {
	data, _ := json.MarshalIndent(st, "", "  ")
	_ = ioutil.WriteFile(stateFile, data, 0600)
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

	// Update global state file path
	stateFile = stateFilePath

	priv, pub, err := loadKey(*homePath)
	if err != nil {
		log.Fatalf("Error loading validator key: %v", err)
	}
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

	var conn net.Conn
	maxRetries := 60 // 1 minute with 1 second intervals

	for attempt := 1; attempt <= maxRetries; attempt++ {
		var err error
		conn, err = net.Dial("tcp", *remoteAddr)
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
			handleConnection(secretConn, priv, pub)
			return
		}

		if attempt == maxRetries {
			log.Fatalf("Failed to dial remote validator after %d attempts: %v", maxRetries, err)
		}

		if debug {
			log.Printf("Connection attempt %d failed: %v. Retrying in 1 second...", attempt, err)
		}
		time.Sleep(1 * time.Second)
	}
}

func handleConnection(conn net.Conn, priv ed25519.PrivKey, pub tmcrypto.PubKey) {
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
			if debug {
				log.Println("SignVoteRequest ", sum.SignVoteRequest.Vote)
			}
			vote := sum.SignVoteRequest.Vote
			chainID := sum.SignVoteRequest.ChainId
			if debug {
				log.Printf("Chain ID: %s", chainID)
			}
			/*
				if !canSign(vote.Height, vote.Round, int8(vote.Type)) {
					log.Printf("Refusing to sign duplicate HRS: %d/%d/%d\n", vote.Height, vote.Round, vote.Type)
					continue
				}
			*/
			// Sign canonical bytes with chain ID (like CometBFT does)
			signBytes := types.VoteSignBytes(chainID, vote)
			sig, err := priv.Sign(signBytes)
			if err != nil {
				log.Printf("Error signing vote: %v", err)
				continue
			}
			vote.Signature = sig
			vote.ValidatorAddress = pub.Address()

			// Handle vote extensions for precommit votes (CometBFT v0.38+)
			if vote.Type == typesproto.PrecommitType {
				// Check if BlockID is nil (zero)
				isNilBlockID := types.ProtoBlockIDIsNil(&vote.BlockID)

				if !isNilBlockID {
					// For non-nil precommit votes, extension signature is required
					// Ensure extension exists (even if empty)
					if vote.Extension == nil {
						vote.Extension = []byte{}
					}

					// Sign vote extension
					extSignBytes := types.VoteExtensionSignBytes(chainID, vote)
					extSig, err := priv.Sign(extSignBytes)
					if err != nil {
						log.Printf("Error signing vote extension: %v", err)
						continue
					}
					vote.ExtensionSignature = extSig
					if debug {
						log.Printf("Signed vote extension for non-nil precommit vote")
					}
				} else {
					// For nil precommit votes, extension signature must NOT be present
					vote.Extension = nil
					vote.ExtensionSignature = nil
					if debug {
						log.Printf("Nil precommit vote - no extension signature")
					}
				}
			}
			saveState(SignerState{Height: vote.Height, Round: vote.Round, Step: int8(vote.Type)})
			resp := &cmproto.Message{
				Sum: &cmproto.Message_SignedVoteResponse{
					SignedVoteResponse: &cmproto.SignedVoteResponse{Vote: *vote},
				},
			}
			sendMsg(conn, resp)

		case *cmproto.Message_SignProposalRequest:
			if debug {
				log.Println("SignProposalRequest ", sum.SignProposalRequest.Proposal)
			}
			prop := sum.SignProposalRequest.Proposal
			chainID := sum.SignProposalRequest.ChainId
			if debug {
				log.Printf("Chain ID: %s", chainID)
			}
			/*
				if !canSign(prop.Height, prop.Round, 2) { // step=2 for proposals
					log.Printf("Refusing to sign duplicate proposal HRS: %d/%d\n", prop.Height, prop.Round)
					continue
				}
			*/
			// Sign canonical bytes with chain ID (like CometBFT does)
			signBytes := types.ProposalSignBytes(chainID, prop)
			sig, err := priv.Sign(signBytes)
			if err != nil {
				log.Printf("Error signing proposal: %v", err)
				continue
			}
			prop.Signature = sig
			saveState(SignerState{Height: prop.Height, Round: prop.Round, Step: 2})
			resp := &cmproto.Message{
				Sum: &cmproto.Message_SignedProposalResponse{
					SignedProposalResponse: &cmproto.SignedProposalResponse{Proposal: *prop},
				},
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

// double-sign protection
func canSign(height int64, round int32, step int8) bool {
	stateLock.Lock()
	defer stateLock.Unlock()

	st := loadState()
	// Reject signing if we've already signed this H/R/S
	if height < st.Height ||
		(height == st.Height && round < st.Round) ||
		(height == st.Height && round == st.Round && step <= st.Step) {
		return false
	}
	return true
}

func sendMsg(conn net.Conn, msg *cmproto.Message) {
	protoWriter := protoio.NewDelimitedWriter(conn)
	if _, err := protoWriter.WriteMsg(msg); err != nil {
		log.Printf("Write message error to %s: %v", conn.RemoteAddr(), err)
		return
	}
}
