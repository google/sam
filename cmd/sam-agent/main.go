package main

import (
	"fmt"
	"os"
)

func main() {
	cfg := &runConfig{}
	cmd := newRootCmd(cfg)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "sam-agent: %v\n", err)
		os.Exit(1)
	}
}
