//go:build linux

package qsortrshim

/*
#cgo CFLAGS: -O2
#include "qsort_r_linux.c"
*/
import "C"
