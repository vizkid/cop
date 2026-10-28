//go:build !cgo

package desktop

import "os"

func Run() { os.Exit(20) }

func RunBatch() { os.Exit(20) }

func RunSession() { os.Exit(20) }
