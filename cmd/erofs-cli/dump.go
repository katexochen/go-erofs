package main

import (
	"flag"
	"fmt"
)

func runDump(args []string) error {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	var path string
	fs.StringVar(&path, "img", "", "Path to erofs image")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("dump: -img is required")
	}
	return fmt.Errorf("dump: not yet implemented")
}
