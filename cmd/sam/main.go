package main

import (
	"fmt"
	"os"
)

func main() {
	cfg := &runConfig{}
	if err := newRootCmd(cfg).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "sam: %v\n", err)
		os.Exit(1)
	}
}
