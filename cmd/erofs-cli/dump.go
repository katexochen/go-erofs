package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/erofs/go-erofs"
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
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(os.Stdout)
	defer func() { _ = w.Flush() }()
	return erofs.Dump(f, w)
}
