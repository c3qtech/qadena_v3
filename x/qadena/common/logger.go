package common

import (
	//	"github.com/cometbft/cometbft/libs/log"
	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	//	kitlevel "github.com/go-kit/log/level"

	//	kitlog "github.com/go-kit/log"
	"fmt"
	"os"
	"strings"
	//"github.com/go-kit/log/term"
)

type qadenaLogger struct {
	srcLogger log.Logger
}

func NewTMLogger(p string) log.Logger {
	loggerPrefix = "[" + p + " - "
	return log.NewLogger(os.Stderr)
}

var loggerPrefix = "[qadena - "

var LogLevelDebugEnabled = false

// SetLogLevel enables or disables debug logging from a CometBFT log_level string.
//
// TWO FORMS, AND THE SECOND ONE USED TO SILENTLY DISABLE EVERYTHING.  A level is either a plain
// name ("debug") or a per-module override list ("p2p:info,consensus:info,*:debug") -- CometBFT
// accepts both, and the list form is the only way to quiet the p2p/consensus/mempool firehose
// without also losing x/qadena's output.  The old implementation switched on the WHOLE string, so
// every list form fell to default and turned LogLevelDebugEnabled off: setting a level whose
// wildcard says "debug" removed all of x/qadena's debug logging, with nothing reporting that it
// had.  That is the worst possible failure for a gate whose only job is deciding what gets
// recorded when something goes wrong.
//
// For the list form the WILDCARD entry governs, because this gate is global -- x/qadena's lines
// are not addressable by module name here, so a per-module entry cannot speak for them.  With no
// wildcard present, any explicit debug entry enables it, on the principle that an operator who
// named debug anywhere wants debug output rather than silence.
func SetLogLevel(level string) {
	LogLevelDebugEnabled = DebugEnabledForLevel(level)
}

// DebugEnabledForLevel reports whether a CometBFT log_level string asks for debug output.
//
// EXPORTED BECAUSE THREE PLACES DECIDED THIS SEPARATELY AND ALL THREE WERE WRONG THE SAME WAY:
// SetLogLevel here, ConfigureEnclaveSupervisor (which picks the level for the SPAWNED enclave
// process, the one producing most of the enclave's debug output), and run_enclave_standalone.sh.
// Each compared the whole string against "debug", so a per-module list quietly meant "no debug"
// in all three -- and because they are separate, a fix to one would have left the others silently
// disagreeing about what the operator asked for.
func DebugEnabledForLevel(level string) bool {
	level = strings.ToLower(strings.TrimSpace(level))

	if !strings.Contains(level, ":") {
		return level == "debug"
	}

	anyDebug := false
	for _, part := range strings.Split(level, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if key == "*" {
			return val == "debug"
		}
		if val == "debug" {
			anyDebug = true
		}
	}
	return anyDebug
}

func LoggerDebug(logger log.Logger, msg string, vals ...interface{}) {
	if !LogLevelDebugEnabled {
		return
	}
	var strArr []string

	strArr = append(strArr, msg)

	for _, v := range vals {
		strArr = append(strArr, fmt.Sprintf("%v", v))
	}

	result := strings.Join(strArr, " ")

	logger.Debug(loggerPrefix + "D]: " + result)
}

func LoggerError(logger log.Logger, msg string, vals ...interface{}) {
	var strArr []string

	strArr = append(strArr, msg)

	for _, v := range vals {
		strArr = append(strArr, fmt.Sprintf("%v", v))
	}

	result := strings.Join(strArr, " ")

	logger.Error(loggerPrefix + "E]: " + result)
}

func LoggerInfo(logger log.Logger, msg string, vals ...interface{}) {
	var strArr []string

	strArr = append(strArr, msg)

	for _, v := range vals {
		strArr = append(strArr, fmt.Sprintf("%v", v))
	}

	result := strings.Join(strArr, " ")

	logger.Info(loggerPrefix + "I]: " + result)
}

func ContextDebug(ctx sdk.Context, msg string, keyvals ...interface{}) {
	if !LogLevelDebugEnabled {
		return
	}
	ctx.Logger().Debug("[qadena]: "+msg, keyvals)
	//LoggerDebug(ctx.Logger(), msg, keyvals...)
}

func ContextError(ctx sdk.Context, msg string, keyvals ...interface{}) {
	LoggerError(ctx.Logger(), msg, keyvals...)
}

func ContextInfo(ctx sdk.Context, msg string, keyvals ...interface{}) {
	LoggerInfo(ctx.Logger(), msg, keyvals...)
}

/*
func LoggerWarn(ctx sdk.Context, msg string, keyvals ...interface{}) {
	ctx.Logger().Warn("[qadena]: "+msg, keyvals)
  }
*/
