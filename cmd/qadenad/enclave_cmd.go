package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var (
	logger                     log.Logger
	debug                      = true
	verbose                    = false
	SupportsUnixDomainSockets  = true
	DefaultPort                = 50051
	addr, signerArg, uniqueArg string
)

const (
	ArmorPassPhrase = "8675309" // this is only used in-process, in the enclave, does not affect security

	// ExportPrivateStateReply carries the whole export in one `string state` field, so its size
	// grows with the chain and there is no page to fall back on.  gRPC's DEFAULT RECEIVE CAP IS
	// 4 MiB and the server's send cap is effectively unbounded, so the enclave builds a reply the
	// client then refuses: at ~10k blocks this began failing with
	//     ResourceExhausted: received message larger than max (8328613 vs 4194304)
	// and every larger chain fails harder.  These commands are one-shot, operator-invoked and run
	// over a local unix socket, so a high cap is the right answer HERE -- it bounds nothing an
	// attacker controls and preallocates nothing.  It is NOT the answer on the consensus paths in
	// x/qadena/keeper, where a reply outgrowing a limit means the message needs paging.
	maxDiagnosticReplyBytes = 512 << 20
)

func NewEnclaveCmd() *cobra.Command {
	logger = c.NewTMLogger("enclave_cmd")

	cmd := &cobra.Command{
		Use:   "enclave",
		Short: "Manage the enclave",
		Long: `Manage the enclave with various subcommands:
check-enclave   - Check the enclave status		
init-enclave    - Initialize enclave for use by the genesis node
sync-enclave    - Sync enclave for use by new full/validator nodes
export-private-key - Export private key (for demo purposes)
remove-private-key - Remove private key from cache (for debug)
export-private-state - Export enclave state (for debug)
update-ss-interval-key - Update SS interval key
height          - Show the enclave's height watermarks
rollback        - Roll the enclave's store back to a chain height`,
	}

	cmd.PersistentFlags().String("addr", "localhost:50051", "the address to connect to")
	cmd.PersistentFlags().String("enclave-signer-id", "", "Enclave signer ID")
	cmd.PersistentFlags().String("enclave-unique-id", "", "Enclave unique ID")

	cmd.AddCommand(
		newCheckEnclaveCmd(),
		newInitEnclaveCmd(),
		newSyncEnclaveCmd(),
		newExportPrivateKeyCmd(),
		newRemovePrivateKeyCmd(),
		newExportPrivateStateCmd(),
		newUpdateSSIntervalKeyCmd(),
		newEnclaveHeightCmd(),
		newEnclaveRollbackCmd(),
		newEnclaveStoreHashCmd(),
		newEnclaveStoreAccumulatorsCmd(),
	)

	return cmd
}

func newEnclaveHeightCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "height",
		Short: "Show the enclave's height watermarks (prepared/confirmed), version, rollback horizon and schema",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}
			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r, err := enclaveClient.GetEnclaveHeight(grpcctx, &types.MsgGetEnclaveHeight{})
			if err != nil {
				return err
			}
			fmt.Printf("preparedHeight:  %d\nconfirmedHeight: %d\nlatestVersion:   %d\nearliestHeight:  %d\nschemaVersion:   %d\n",
				r.PreparedHeight, r.ConfirmedHeight, r.LatestVersion, r.EarliestHeight, r.SchemaVersion)
			return nil
		},
	}
}

// newEnclaveStoreHashCmd exposes the enclave's per-store hashes.
//
// This is the primitive that answers "did the ENCLAVE actually roll back?", as opposed to "did
// its watermark move".  Capture it before a transaction, roll back past that transaction, and
// capture it again: identical hashes prove the enclave's STATE reverted, not merely its
// bookkeeping.
//
// It works on a REAL SGX enclave as well as a debug one, which export-private-state does not --
// it returns hashes of the stores, never their contents, so nothing sealed leaves the enclave.
// These are the same nine mirror prefixes the chain compares against its own copies at startup.
func newEnclaveStoreHashCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "store-hash",
		Short: "Show the enclave's per-store hashes (works on real SGX; reveals no contents)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}
			grpcctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			r, err := enclaveClient.GetStoreHash(grpcctx, &types.MsgGetStoreHash{})
			if err != nil {
				return err
			}
			for _, h := range r.GetHashes() {
				fmt.Printf("%s %s\n", h.GetHash(), h.GetKey())
			}
			return nil
		},
	}
}

func newEnclaveStoreAccumulatorsCmd() *cobra.Command {
	var height int64
	cmd := &cobra.Command{
		Use:   "store-accumulators",
		Short: "Show the enclave's per-store accumulators (digests only -- safe on real SGX); --height reads history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}
			grpcctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			r, err := enclaveClient.GetStoreAccumulators(grpcctx, &types.MsgGetStoreAccumulators{Height: height})
			if err != nil {
				return err
			}
			for _, e := range r.GetAccumulators() {
				if !e.GetPresent() {
					// Only reachable with --height: an accumulator did not exist before the block
					// that established it, and absent is reported honestly rather than as zero.
					fmt.Printf("%-64s %s (absent at this height)\n", "-", e.GetKey())
					continue
				}
				fmt.Printf("%x %s rows=%d\n", e.GetAcc(), e.GetKey(), e.GetRows())
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&height, "height", 0, "read the accumulators as of this chain height (0 = current; current establishes any missing value first)")
	return cmd
}

func newEnclaveRollbackCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "rollback [height]",
		Short: "Roll the enclave's store back to the state it committed for a chain height",
		Long: `Roll the enclave's versioned store back to the state it committed for the given chain
height.  The secrets DB (SS interval keys) is never touched.

ONLY run this with qadenad STOPPED: rolling back under a live chain corrupts the block in
flight.  Normally this command is not needed at all -- 'qadenad rollback' rolls chain and
enclave together -- it exists for recovery situations where the two must be moved separately.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			height, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid height %q: %w", args[0], err)
			}
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}
			// a deep rollback rebuilds the IAVL fast-node index; give it real time
			grpcctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			r, err := enclaveClient.RollbackToHeight(grpcctx, &types.MsgRollbackToHeight{Height: height, DryRun: dryRun})
			if err != nil {
				return err
			}
			if r.RolledBack {
				fmt.Printf("rolled back: height %d (version %d) -> height %d (version %d)\n", r.FromHeight, r.FromVersion, r.ToHeight, r.ToVersion)
			} else {
				fmt.Printf("not rolled back: %s\n", r.Reason)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would happen without touching anything")
	return cmd
}

func newCheckEnclaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check-enclave",
		Short: "Check the enclave status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// AN ANSWERED RPC, not a constructed dial.  grpc.Dial is LAZY: it returns a
			// ClientConn without connecting to anything and defers that to the first call.  So
			// this command used to report "Enclave is running" whenever the ADDRESS PARSED --
			// true with nothing listening at all -- which made every caller's readiness poll
			// vacuous.
			//
			// add_full_node.sh polls this up to 90 times before running sync-enclave.  On a debug
			// box the enclave happened to be serving by then and the bug stayed hidden; on real
			// SGX, `[erthost] loading enclave` takes tens of seconds, the poll passed on its first
			// try against nothing, and sync-enclave -- the first REAL rpc -- died with
			//     rpc error: code = Unavailable desc = error reading from server: EOF
			// which reads like a peer problem and is in fact "we never waited".
			//
			// Waiting longer would not have fixed it: the check has to require a ROUND TRIP.
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				c.LoggerError(logger, "Enclave is not running", err)
				os.Exit(10)
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// GetEnclaveStatus is a read with no side effects, so it is safe to call before the
			// enclave has been initialized -- which is exactly when this is polled.  An enclave
			// too old to have it answers Unimplemented, and that is still proof it is SERVING:
			// the request reached a running gRPC server and was understood well enough to be
			// refused, so treat it as up rather than demanding a newer enclave.
			if _, err := enclaveClient.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{}); err != nil {
				if status.Code(err) != codes.Unimplemented {
					c.LoggerError(logger, "Enclave is not answering", err)
					os.Exit(10)
					return err
				}
			}

			c.LoggerInfo(logger, "Enclave is running")
			os.Exit(0)
			return nil
		},
	}
}

func newSyncEnclaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync-enclave [PioneerID] [Advertise-IP-Address] [SeedNodeURI]",
		Short: "Sync enclave for use by new full/validator nodes",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			_, _, _, _, armorPrivK, err := c.GetAddressByName(ctx, args[0], ArmorPassPhrase)
			if err != nil {
				return err
			}

			e := types.MsgSyncEnclave{
				PioneerID:              args[0],
				ExternalAddress:        args[1],
				PioneerArmorPrivK:      armorPrivK,
				PioneerArmorPassPhrase: ArmorPassPhrase,
				SeedNode:               args[2],
			}
			// WAIT FOR THE ENCLAVE TO BE SERVING, rather than trusting the caller to have waited.
			//
			// "The enclave is still loading" is a normal state, not an error: on real SGX
			// `[erthost] loading enclave` takes tens of seconds before anything listens.  This
			// call is the FIRST real RPC in the promotion flow, so it is where that shows up --
			// as `Unavailable: error reading from server: EOF`, which reads like the peer refused
			// us and actually means nobody was home yet.  add_full_node.sh does poll first, but a
			// correctness property should not rest on every caller polling correctly; it already
			// failed to once, when check-enclave's poll turned out to be vacuous.
			if err := awaitEnclaveServing(enclaveClient, 3*time.Minute); err != nil {
				c.LoggerError(logger, "the enclave never started serving", err)
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.SyncEnclave(grpcctx, &e)
			if err != nil {
				c.LoggerError(logger, "could not sync enclave", err)
				return err
			}
			c.LoggerDebug(logger, "SyncEnclave returns", r2)
			if r2.Status {
				c.LoggerInfo(logger, "SyncEnclave SUCCEEDED")
				return nil
			}

			return fmt.Errorf("init enclave failed")
		},
	}
}

func newInitEnclaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init-enclave [PioneerID] [Advertise-IP-Address] [JarID] [RegulatorID]",
		Short: "Initialize enclave for use by the genesis node",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}
			signerID, _ := cmd.Flags().GetString("enclave-signer-id")
			uniqueID, _ := cmd.Flags().GetString("enclave-unique-id")

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			_, _, _, _, armorPrivK, err := c.GetAddressByName(ctx, args[0], ArmorPassPhrase)
			if err != nil {
				return err
			}

			e := types.MsgInitEnclave{
				PioneerID:              args[0],
				ExternalAddress:        args[1],
				JarID:                  args[2],
				RegulatorID:            args[3],
				PioneerArmorPrivK:      armorPrivK,
				PioneerArmorPassPhrase: ArmorPassPhrase,
				SignerID:               signerID,
				UniqueID:               uniqueID,
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.InitEnclave(grpcctx, &e)
			if err != nil {
				c.LoggerError(logger, "could not init enclave", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "InitEnclave returns", r2)
			}
			if r2.Status {
				return nil
			}
			return fmt.Errorf("init enclave failed")
		},
	}
}

func newExportPrivateKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export-private-key [pubKID]",
		Short: "Export private key for a given pubKID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.ExportPrivateKey(grpcctx, &types.MsgExportPrivateKey{
				PubKID: args[0],
			})
			if err != nil {
				c.LoggerError(logger, "could not export private key", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "ExportPrivateKey returns", r2)
			}

			return nil
		},
	}
}

func newRemovePrivateKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-private-key [pubKID]",
		Short: "Remove private key for a given pubKID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.RemovePrivateKey(grpcctx, &types.MsgRemovePrivateKey{
				PubKID: args[0],
			})
			if err != nil {
				c.LoggerError(logger, "could not remove private key", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "RemovePrivateKey returns", r2)
			}

			return nil
		},
	}
}

// newExportPrivateStateCmd dumps the enclave's private state, or -- with --digest-only -- just
// enough to tell whether two enclaves hold the SAME private state without moving any of it.
//
// The digest exists because the dump does not scale and cannot be made to.  Its reply is one JSON
// document that grows with the chain, and at ~10k blocks on the two-node testnet it passed gRPC's
// 4 MiB default receive cap and the command simply stopped working -- exactly when there was most
// to compare.  --digest-only returns a fixed handful of rows no matter how large the chain gets,
// so the comparison is O(sections) and the content dump is needed only for a section that already
// disagreed, which --section then fetches on its own.
//
// WHY THE DIGESTS ARE COMPARABLE AT ALL: rows live under stable-sealed keys and stable sealing is
// per-node, so neither the raw bytes nor the store's iteration order match between two correct
// enclaves.  The enclave hashes the UNSEALED content with array sections sorted, which is the
// logical state both nodes should agree on.
func newExportPrivateStateCmd() *cobra.Command {
	var height int64
	var digestOnly bool
	var section string
	var maxBytes uint64
	cmd := &cobra.Command{
		Use:   "export-private-state",
		Short: "Export enclave private state, or --digest-only to compare two enclaves cheaply",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
			defer cancel()
			r2, err := enclaveClient.ExportPrivateState(grpcctx, &types.MsgExportPrivateState{
				Height:     height,
				DigestOnly: digestOnly,
				Section:    section,
				MaxBytes:   maxBytes,
			})
			if err != nil {
				c.LoggerError(logger, "could not export private state", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "ExportPrivateState returns", r2)
			}

			if digestOnly {
				// Tab-separated and one section per line, so comparing two nodes is a diff.
				for _, d := range r2.GetDigests() {
					fmt.Printf("%s\t%d\t%s\t%d\n", d.GetName(), d.GetRows(), d.GetSha256(), d.GetBytes())
				}
				return nil
			}

			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, []byte(r2.State), "", "    "); err != nil {
				c.LoggerError(logger, "could not format JSON", err)
				return err
			}
			fmt.Println(prettyJSON.String())

			return nil
		},
	}
	cmd.Flags().Int64Var(&height, "height", 0, "dump the enclave's state as of this chain height (0 = current)")
	cmd.Flags().BoolVar(&digestOnly, "digest-only", false, "print name/rows/sha256/bytes per section instead of the content -- the reply cannot outgrow the transport")
	cmd.Flags().StringVar(&section, "section", "", "dump only this section (see --digest-only for the names)")
	cmd.Flags().Uint64Var(&maxBytes, "max-bytes", 0, "refuse a content dump larger than this, naming the section that blew the budget (0 = built-in default)")
	return cmd
}

func newUpdateSSIntervalKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-ss-interval-key",
		Short: "Update the interval key for the private state",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.UpdateSSIntervalKey(grpcctx, &types.MsgUpdateSSIntervalKey{})
			if err != nil {
				c.LoggerError(logger, "could not update the interval key for the private state", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "UpdateSSIntervalKey returns", r2)
			}

			return nil
		},
	}
}

// Helper function to get gRPC connection
func getEnclaveConnection(cmd *cobra.Command) (types.QadenaEnclaveClient, error) {
	var conn *grpc.ClientConn
	var err error

	if SupportsUnixDomainSockets {
		addr = fmt.Sprintf("unix:///tmp/qadena_%d.sock", DefaultPort)

		if debug {
			c.LoggerDebug(logger, "Will connect to QadenaDEnclave (unix domain socket)", addr)
		}
		conn, err = grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithTimeout(time.Duration(5)*time.Second),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxDiagnosticReplyBytes)))
	} else {
		c.LoggerError(logger, "Not supported", err)
		return nil, fmt.Errorf("not supported")
	}

	if err != nil {
		c.LoggerError(logger, "Did not connect", err)
		return nil, err
	}

	greeterClient := types.NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := greeterClient.SayHello(ctx, &types.HelloRequest{Name: "Pong"})
	if err != nil {
		c.LoggerError(logger, "Could not greet", err)
		return nil, err
	}
	if debug {
		c.LoggerDebug(logger, "Greeting", r.GetMessage())
	}

	enclaveClient := types.NewQadenaEnclaveClient(conn)

	return enclaveClient, nil
}

// awaitEnclaveServing blocks until the enclave answers an RPC, or the deadline passes.
//
// The distinction that matters: a CONNECTION FAILURE means "not serving yet" and is worth waiting
// on, while any answer -- including Unimplemented from an enclave too old to know the method --
// means the server is up and we should stop waiting.  Unavailable and the EOF that a not-yet-bound
// unix socket produces are the transient shapes; anything else is a real answer.
//
// Exists because grpc.Dial is lazy, so "I have a connection" is not evidence of anything, and
// because SGX enclave startup is slow enough that the gap is measured in tens of seconds rather
// than milliseconds.  Both facts are invisible on a debug build, which is why this went unnoticed
// until a real SGX joiner tried to promote.
func awaitEnclaveServing(enclaveClient types.QadenaEnclaveClient, within time.Duration) error {
	deadline := time.Now().Add(within)
	var lastErr error
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := enclaveClient.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{})
		cancel()
		if err == nil || status.Code(err) == codes.Unimplemented {
			if attempt > 1 {
				c.LoggerInfo(logger, "the enclave is serving (it needed", attempt, "attempts -- SGX enclave loading is slow)")
			}
			return nil
		}
		lastErr = err
		if status.Code(err) != codes.Unavailable {
			// A real, non-transport answer: waiting will not improve it.
			return err
		}
		if attempt == 1 || attempt%10 == 0 {
			c.LoggerInfo(logger, "waiting for the enclave to start serving (attempt", attempt, ")")
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("the enclave did not start serving within %s: %w", within, lastErr)
}
