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

var LogLevelDebugEnabled = true

// SetLogLevel enables or disables debug logging based on a simple level string.
// If level is "debug" (case-insensitive), debug logs are emitted; otherwise they are suppressed.
func SetLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		LogLevelDebugEnabled = true
	default:
		LogLevelDebugEnabled = false
	}
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
