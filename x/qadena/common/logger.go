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
	return log.NewLogger(os.Stdout)
}

var loggerPrefix = "[qadena - "

func LoggerDebug(logger log.Logger, msg string, vals ...interface{}) {
	var strArr []string

	strArr = append(strArr, msg)

	for _, v := range vals {
		strArr = append(strArr, fmt.Sprintf("%v", v))
	}

	result := strings.Join(strArr, " ")

	logger.Info(loggerPrefix + "D]: " + result)
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
	//	ctx.Logger().Debug("[qadena]: "+msg, keyvals)
	LoggerDebug(ctx.Logger(), msg, keyvals...)
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
