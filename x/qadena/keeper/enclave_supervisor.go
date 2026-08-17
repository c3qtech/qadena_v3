package keeper

// The enclave supervisor: qadenad spawns and owns its enclave processes.
//
// Before this file, a Qadena node was five cooperating shell scripts in a strict order -- run.sh
// started the chain enclave (respawn loop), polled it, started the signer enclave, polled it,
// backgrounded delayed_init_enclave.sh, and started qadenad LAST -- because the chain panics in
// app.New if the enclave socket does not answer.  Every piece of that machinery re-derived state
// qadenad already holds: the pruning flags were grepped out of app.toml, the chain id out of
// genesis.json, the log level out of config.toml, readiness out of a 90-round poll of the very
// socket InitEnclave dials anyway.  Now InitEnclave spawns the processes itself, with the values
// taken from where they actually live (appOpts), and the scripts collapse to "qadenad start".
//
// CRASH POLICY: a spawned enclave that exits takes THE NODE with it -- a named, non-zero exit, so
// the process supervisor (systemd Restart=on-failure) restarts the node and the well-tested
// startup reconcile path does the recovery.  There is deliberately NO in-process respawn loop:
// the old `while true` loops were also what made a genuinely broken enclave respawn forever,
// invisibly, and an enclave death mid-block already ended in a halt (the in-flight calls fail and
// haltOnEnclaveFailure panics), so the loop only ever saved an idle crash -- at the price of
// hiding every crash it "recovered".  A HUNG enclave (alive but unresponsive) still takes the
// watchdog path, unchanged.
//
// ADOPTION: if an enclave is already serving on the socket when we would spawn, we use it and
// leave it alone -- not spawned by us, not stopped by us, not monitored by us (the watchdog still
// owns liveness).  That is what makes the debugger workflow (`run_enclave_standalone.sh` +
// `qadenad start --external-enclave`), the post-halt restart (the orphaned enclave keeps its
// state and the restarted node picks it up), and the rollback command's "use it if it's there"
// semantics all fall out of one rule.
//
// MRENCLAVE: this file is chain-side only.  The enclave binary is spawned with exactly the argv
// the deleted scripts used; nothing in cmd/qadenad_enclave changes.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/spf13/cast"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// Spawn modes.  The zero value ("") is dial-only: every app-constructing command that has not
// explicitly opted in (export, in-place-testnet, ...) behaves exactly as before -- it requires an
// externally running enclave and spawns nothing, because a short-lived command must not leak
// child processes.
const (
	SpawnModeNone     = ""
	SpawnModeStart    = "start"    // chain enclave + signer enclave
	SpawnModeRollback = "rollback" // chain enclave only; caller stops it via StopSpawnedEnclaves
)

var (
	enclaveSpawnMode string

	// --external-enclave: the CHAIN enclave is externally managed (a debugger, typically) and
	// must not be spawned -- but the SIGNER still is.  The signer is the node's remote block
	// signer (config.toml priv_validator_laddr); without one this node cannot sign, so "run the
	// chain enclave under a debugger" must not silently also mean "bring your own signer".
	// This mirrors the old run.sh --no-qadenad-enclave, which skipped the chain enclave and
	// always started the signer.
	externalChainEnclave bool

	// Derived from appOpts in ConfigureEnclaveSupervisor; consumed by prepareEnclaveProcesses.
	supervisorHome     string
	supervisorLogLevel string
	supervisorPruning  [3]string // strategy, keep-recent, interval

	spawnedEnclaves    []*spawnedEnclave
	supervisorShutdown atomic.Bool
	signalForwardOnce  sync.Once
)

type spawnedEnclave struct {
	name string
	cmd  *exec.Cmd
	done chan struct{} // closed by the monitor goroutine after Wait returns
}

// EnableEnclaveSpawn opts the current command into spawning.  Called from the start command's
// PreRunE (SpawnModeStart) and from the rollback command (SpawnModeRollback) -- before app.New
// runs, which is what makes the per-command policy work with a single InitEnclave.
func EnableEnclaveSpawn(mode string) { enclaveSpawnMode = mode }

// SetExternalChainEnclave marks the chain enclave as externally managed (--external-enclave).
func SetExternalChainEnclave(v bool) { externalChainEnclave = v }

// ConfigureEnclaveSupervisor derives everything a spawn needs from the app options, once, in
// app.New, immediately before InitEnclave.  The values come from where they actually live --
// appOpts already reflects app.toml plus flags -- instead of the deleted scripts' greps of
// app.toml/config.toml.  Safe to call under every command; it only records values.
func ConfigureEnclaveSupervisor(logger log.Logger, appOpts servertypes.AppOptions) {
	supervisorHome = cast.ToString(appOpts.Get(flags.FlagHome))

	// Parity with run.sh: anything that is not exactly "debug" runs the enclave at info.
	supervisorLogLevel = "info"
	if cast.ToString(appOpts.Get("log_level")) == "debug" {
		supervisorLogLevel = "debug"
	}

	// The chain's pruning window, handed to the enclave at spawn.  The enclave must retain at
	// least as much history as the chain, or a rollback the chain accepts fails on the enclave.
	// Passed as flags because the enclave sets retention before it loads its store.
	supervisorPruning[0] = cast.ToString(appOpts.Get("pruning"))
	supervisorPruning[1] = cast.ToString(appOpts.Get("pruning-keep-recent"))
	supervisorPruning[2] = cast.ToString(appOpts.Get("pruning-interval"))
	if supervisorPruning[0] == "" {
		supervisorPruning[0] = "default"
	}
	if supervisorPruning[1] == "" {
		supervisorPruning[1] = "0"
	}
	if supervisorPruning[2] == "" {
		supervisorPruning[2] = "0"
	}
}

// EnclaveRealMode reports whether the installed chain-enclave binary must run under `ego run`:
// the CPU supports SGX AND the binary carries an ego signature.  Mirrors use_real_enclave in the
// deleted scripts: the cpuinfo flag alone only says the CPU could, not that this binary was built
// for it.  Exported because the init dispatch needs the same answer to decide between real
// measurement ids and the debug "*".
func EnclaveRealMode(home string) bool {
	return hostSupportsSGX() && binaryIsEgoSigned(filepath.Join(home, "bin", "qadenad_enclave"))
}

func hostSupportsSGX() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	return err == nil && strings.Contains(string(cpuinfo), "sgx")
}

func binaryIsEgoSigned(bin string) bool {
	ego, err := exec.LookPath("ego")
	if err != nil {
		return false
	}
	out, err := exec.Command(ego, "uniqueid", bin).Output()
	// ego reports failure on STDOUT (not stderr) with exit 1; both checks for safety.
	return err == nil && !strings.HasPrefix(strings.TrimSpace(string(out)), "ERROR")
}

// EgoID runs `ego signerid`/`ego uniqueid` and returns the measurement, with ego's
// report-failure-on-stdout quirk handled: a captured "ERROR: ..." is a failure, not an id.
func EgoID(kind string, target string) (string, error) {
	out, err := exec.Command("ego", kind, target).Output()
	id := strings.TrimSpace(string(out))
	if err != nil || id == "" || strings.HasPrefix(id, "ERROR") {
		return "", fmt.Errorf("ego %s %s failed: %s", kind, target, id)
	}
	return id, nil
}

// sgxDevicePreflight is the in-process replacement for the scripts' needs_root_if_real_enclave
// heuristic, asked by the process that actually needs the answer: can the enclave we are about to
// spawn open the SGX devices?  Children inherit our uid, so if we can open them, so can they.
// The PREFERRED remedy is group membership, not root -- running the stack as root is what created
// the root-owned-socket and root-owned-build-tree problems the old scripts had cleanup code for.
func sgxDevicePreflight() error {
	dev := firstExisting("/dev/sgx_enclave", "/dev/sgx/enclave")
	prov := firstExisting("/dev/sgx_provision", "/dev/sgx/provision")
	if dev == "" || prov == "" {
		return fmt.Errorf("the enclave binary is ego-signed and the CPU supports SGX, but the SGX device nodes are missing (looked for /dev/sgx_enclave and /dev/sgx_provision) -- is the SGX driver loaded?")
	}
	for _, p := range []string{dev, prov} {
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("cannot open %s: %v -- the spawned enclave would inherit this refusal.  Either add this user to the sgx groups (preferred: ls -l %s and usermod -aG <group> %s), or run qadenad as root (discouraged: it leaves root-owned sockets and files behind)", p, err, p, userName())
		}
		f.Close()
	}
	return nil
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func userName() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "<user>"
}

// prepareEnclaveProcesses runs at the top of InitEnclave.  It returns how many dial attempts the
// caller should make: 5 (the historical count) when nothing was spawned, 90 when a spawn is
// warming up -- the same 90x1s the deleted run.sh poll allowed, which real SGX cold starts need.
//
// Failures here PANIC with named causes rather than returning false into app.New's generic
// "Unable to connect to enclave": every one of them (missing binary, unreadable genesis, SGX
// device permissions) has a specific remedy the operator should be told.
func prepareEnclaveProcesses(logger log.Logger) int {
	if enclaveSpawnMode == SpawnModeNone {
		return 5
	}

	home := supervisorHome
	if home == "" {
		panic("enclave supervisor: no home directory configured -- ConfigureEnclaveSupervisor did not run before InitEnclave")
	}

	// An enclave already serving (started externally, or orphaned by a panicking node) is USED,
	// not replaced: we neither stop nor restart it, and it is absent from spawnedEnclaves so the
	// crash policy and the shutdown path leave it alone.  The watchdog still owns its liveness.
	// The signer is judged separately below -- adopting a chain enclave says nothing about it.
	adopted := enclaveSocketAnswers()
	if adopted {
		c.LoggerInfo(logger, "an enclave is already serving on the socket -- adopting it (externally managed: this node will not stop or restart it; the watchdog still owns liveness)")
	}
	if externalChainEnclave && !adopted {
		c.LoggerInfo(logger, "--external-enclave: not spawning the chain enclave; waiting for one to appear on the socket")
	}

	// The SIGNER is spawned regardless of who owns the chain enclave: it is this node's remote
	// block signer (priv_validator_laddr), not part of the debugging surface.
	if enclaveSpawnMode == SpawnModeStart && !signerSocketAnswers() {
		spawnSignerEnclave(logger, home)
	}

	if adopted || externalChainEnclave {
		if externalChainEnclave && !adopted {
			return 90 // give the operator time to start theirs
		}
		return 5
	}

	chainID, err := chainIDFromGenesis(filepath.Join(home, "config", "genesis.json"))
	if err != nil {
		panic(fmt.Sprintf("enclave supervisor: cannot read the chain id the enclave needs: %v", err))
	}

	// Parity with run_enclave.sh: the enclave creates nothing above its own stores.
	for _, d := range []string{"enclave_config", "enclave_data", "enclave_secrets"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			panic(fmt.Sprintf("enclave supervisor: cannot create %s: %v", filepath.Join(home, d), err))
		}
	}

	spawnChainEnclave(logger, home, chainID)
	return 90
}

// signerSocketAnswers reports whether something is already serving the signer's health endpoint,
// so a restart onto an orphaned signer adopts it instead of starting a second one that would
// fail to bind.
func signerSocketAnswers() bool {
	httpc := &http.Client{Timeout: time.Second}
	resp, err := httpc.Get("http://localhost:26661/ping")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// enclaveSocketAnswers is the adoption probe: one quick dial+ping of the fixed socket.
func enclaveSocketAnswers() bool {
	sock := fmt.Sprintf("/tmp/qadena_%d.sock", DefaultPort)
	if _, err := os.Stat(sock); err != nil {
		return false
	}
	// A socket FILE can be stale (dead server).  Only an answered ping counts.
	return pingEnclaveSocket(2 * time.Second)
}

func chainIDFromGenesis(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var g struct {
		ChainID string `json:"chain_id"`
	}
	if err := json.NewDecoder(f).Decode(&g); err != nil {
		return "", fmt.Errorf("parsing %s: %w", path, err)
	}
	if g.ChainID == "" {
		return "", fmt.Errorf("%s has no chain_id", path)
	}
	return g.ChainID, nil
}

func spawnChainEnclave(logger log.Logger, home, chainID string) {
	bin := filepath.Join(home, "bin", "qadenad_enclave")
	if _, err := os.Stat(bin); err != nil {
		panic(fmt.Sprintf("enclave supervisor: no enclave binary at %s -- install it (install.sh --enclave) or start one externally and pass --external-enclave", bin))
	}

	// Exactly the argv the deleted run_enclave.sh/run_realenclave.sh used.
	args := []string{
		"--home=" + home,
		"--chain-id=" + chainID,
		"--log-level", supervisorLogLevel,
		"--pruning=" + supervisorPruning[0],
		"--pruning-keep-recent=" + supervisorPruning[1],
		"--pruning-interval=" + supervisorPruning[2],
	}

	var cmd *exec.Cmd
	if EnclaveRealMode(home) {
		if err := sgxDevicePreflight(); err != nil {
			panic("enclave supervisor: " + err.Error())
		}
		cmd = exec.Command("ego", append([]string{"run", bin, "--realenclave"}, args...)...)
	} else {
		cmd = exec.Command(bin, args...)
	}
	startChild(logger, "qadenad_enclave", cmd)
}

func spawnSignerEnclave(logger log.Logger, home string) {
	bin := filepath.Join(home, "bin", "signer_enclave")
	if _, err := os.Stat(bin); err != nil {
		panic(fmt.Sprintf("enclave supervisor: no signer enclave binary at %s -- install it (install.sh --signer-enclave)", bin))
	}

	args := []string{"--home=" + home, "--addr=127.0.0.1:26659"}

	var cmd *exec.Cmd
	// Judged on ITS OWN binary, as the scripts did: the two enclaves are built separately, so one
	// being signed says nothing about the other.  (And yes, the signer spells its flag
	// --real-enclave where the chain enclave spells it --realenclave; both are load-bearing.)
	if hostSupportsSGX() && binaryIsEgoSigned(bin) {
		if err := sgxDevicePreflight(); err != nil {
			panic("enclave supervisor: " + err.Error())
		}
		cmd = exec.Command("ego", append([]string{"run", bin, "--real-enclave"}, args...)...)
	} else {
		cmd = exec.Command(bin, args...)
	}
	startChild(logger, "signer_enclave", cmd)
}

func startChild(logger log.Logger, name string, cmd *exec.Cmd) {
	// The children write into the same stdout/stderr as qadenad, so their logs keep landing in
	// the same rotatelogs/journal pipe the node's do -- exactly where run.sh used to put them.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		panic(fmt.Sprintf("enclave supervisor: could not start %s: %v", name, err))
	}
	child := &spawnedEnclave{name: name, cmd: cmd, done: make(chan struct{})}
	spawnedEnclaves = append(spawnedEnclaves, child)
	c.LoggerInfo(logger, fmt.Sprintf("spawned %s (pid %d)", name, cmd.Process.Pid))

	installSignalForwarding()
	go monitorChild(logger, child)
}

// installSignalForwarding makes a clean node shutdown take the children along: on SIGINT/SIGTERM
// we mark the supervisor as shutting down (so monitorChild reads the exits as expected) and
// forward SIGINT, on which the enclave exits 20 cleanly.  This subscribes alongside the cosmos
// server's own handler; signal.Notify supports multiple subscribers.
func installSignalForwarding() {
	signalForwardOnce.Do(func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-ch
			supervisorShutdown.Store(true)
			for _, child := range spawnedEnclaves {
				_ = child.cmd.Process.Signal(os.Interrupt)
			}
		}()
	})
}

// monitorChild is the crash policy.  A child that exits while the node is running cancels the
// enclave-alive root with a named cause -- so anything blocked in an enclave call unblocks into
// haltOnEnclaveFailure -- and then exits the PROCESS non-zero, so systemd restarts the node and
// startup reconciliation recovers.  Strictly faster and louder than before: an idle enclave death
// used to take the watchdog's 2-minute grace to surface; this surfaces on the Wait.
func monitorChild(logger log.Logger, child *spawnedEnclave) {
	err := child.cmd.Wait()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	} else if child.cmd.ProcessState != nil {
		code = child.cmd.ProcessState.ExitCode()
	}
	close(child.done)

	if supervisorShutdown.Load() {
		c.LoggerInfo(logger, fmt.Sprintf("%s stopped (exit %d) during shutdown", child.name, code))
		return
	}

	cause := fmt.Errorf("%s process exited unexpectedly (code %d) -- halting the node so the supervisor can restart it; startup reconciliation will recover", child.name, code)
	c.LoggerError(logger, cause.Error())
	enclaveAliveCancel(cause)
	// Give in-flight calls a moment to unblock into the named halt path and log, then make the
	// exit certain -- an idle node has no in-flight call to panic for it.
	time.Sleep(2 * time.Second)
	os.Exit(1)
}

// StopSpawnedEnclaves stops every child THIS process spawned (adopted external enclaves are left
// alone -- they are not in the list).  Used by the rollback command to be self-contained, and by
// InitEnclave's failure path so a node that cannot come up does not leave children behind.
// SIGINT first (the enclave's clean exit), SIGKILL for anything still alive after the grace.
func StopSpawnedEnclaves() {
	supervisorShutdown.Store(true)
	for _, child := range spawnedEnclaves {
		_ = child.cmd.Process.Signal(os.Interrupt)
	}
	deadline := time.After(30 * time.Second)
	for _, child := range spawnedEnclaves {
		select {
		case <-child.done:
		case <-deadline:
			_ = child.cmd.Process.Kill()
			<-child.done
		}
	}
	spawnedEnclaves = nil
}

// signerEnclaveSpawned reports whether this process spawned a signer (start mode, not adopted).
func signerEnclaveSpawned() bool {
	for _, child := range spawnedEnclaves {
		if child.name == "signer_enclave" {
			return true
		}
	}
	return false
}

// awaitSignerEnclave is the readiness gate run.sh:114-130 used to be: poll the signer's health
// endpoint up to 90x1s before declaring the node up.  Only meaningful when we spawned one.
func awaitSignerEnclave(logger log.Logger) error {
	if !signerEnclaveSpawned() {
		return nil
	}
	httpc := &http.Client{Timeout: time.Second}
	for i := 0; i < 90; i++ {
		resp, err := httpc.Get("http://localhost:26661/ping")
		if err == nil {
			resp.Body.Close()
			c.LoggerInfo(logger, "signer_enclave is up")
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("signer_enclave did not answer http://localhost:26661/ping within 90s")
}
