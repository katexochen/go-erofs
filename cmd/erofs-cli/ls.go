package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/erofs/go-erofs"
)

func runLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	var path string
	fs.StringVar(&path, "img", "", "Path to erofs image")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("ls: -img is required")
	}
	return lsImage(path)
}

func lsImage(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	img, err := erofs.Open(f)
	if err != nil {
		return err
	}

	fmt.Printf("Found valid image...\n")

	return fs.WalkDir(img, "/", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error visiting %s: %w", path, err)
		}
		fmt.Printf("visited: %q\n", path)
		fmt.Printf("\tName: %q\n", entry.Name())
		fmt.Printf("\tType: %o\n", entry.Type())
		if entry.IsDir() {
			fmt.Printf("\tIs a directory: yes\n")
		} else {
			fmt.Printf("\tIs a directory: no\n")
		}
		fi, err := entry.Info()
		if err != nil {
			return fmt.Errorf("error getting info for %s: %w", path, err)
		}
		fmt.Printf("\tMode: %o\n", fi.Mode())
		fmt.Printf("\tModTime: %s\n", fi.ModTime())
		st := fi.Sys().(*erofs.Stat)
		if len(st.Xattrs) > 0 {
			fmt.Printf("\tXattrs:\n")
			for k, v := range st.Xattrs {
				fmt.Printf("\t\t%s: %q\n", k, v)
			}
		}
		// Hash the content of regular files and symlinks. For symlinks the
		// "content" is the target string. Directories, devices, fifos, and
		// sockets have no content layer to hash.
		switch {
		case entry.Type()&fs.ModeType == 0:
			sum, err := hashFile(img, path)
			if err != nil {
				fmt.Printf("\tSHA256: <error: %v>\n", err)
			} else {
				fmt.Printf("\tSHA256: %x\n", sum)
			}
		case entry.Type()&fs.ModeSymlink != 0:
			target, err := fs.ReadLink(img, path)
			if err != nil {
				fmt.Printf("\tSHA256: <error: %v>\n", err)
			} else {
				sum := sha256.Sum256([]byte(target))
				fmt.Printf("\tSHA256: %x  (symlink target)\n", sum[:])
			}
		}
		if entry.Name() == "." || entry.Name() == ".." {
			return fs.SkipDir
		}
		return nil
	})
}

func hashFile(fsys fs.FS, path string) ([]byte, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
