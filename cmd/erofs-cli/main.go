package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s <subcommand> [flags]

Subcommands:
  ls    walk the filesystem and print per-entry metadata via fs.FS
  dump  print on-disk internals (superblock, inodes, dirents, xattrs, ...)
        in a deterministic, diff-friendly text format

Run "%s <subcommand> -h" for subcommand-specific flags.
`, os.Args[0], os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	var err error
	switch sub {
	case "ls":
		err = runLs(args)
	case "dump":
		err = runDump(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
