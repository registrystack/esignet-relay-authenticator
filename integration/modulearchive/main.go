// modulearchive verifies Go's h1 module-zip checksum before extracting source.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func extract(archive, prefix, expected, destination string) error {
	source, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer source.Close()
	files := append([]*zip.File(nil), source.File...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	total := sha256.New()
	previous := ""
	for _, file := range files {
		if file.Name == previous || strings.Contains(file.Name, "\n") {
			return fmt.Errorf("invalid module archive entry")
		}
		previous = file.Name
		if !strings.HasPrefix(file.Name, prefix+"/") {
			return fmt.Errorf("unexpected module archive prefix")
		}
		relative := strings.TrimPrefix(file.Name, prefix+"/")
		if !filepath.IsLocal(relative) || file.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("invalid module archive path")
		}
		stream, err := file.Open()
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, stream)
		closeErr := stream.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Fprintf(total, "%x  %s\n", hash.Sum(nil), file.Name)
	}
	actual := "h1:" + base64.StdEncoding.EncodeToString(total.Sum(nil))
	if actual != expected {
		return fmt.Errorf("module archive checksum mismatch")
	}
	// Extract only after all bytes match the independently pinned module checksum.
	for _, file := range files {
		target := filepath.Join(destination, strings.TrimPrefix(file.Name, prefix+"/"))
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if file.Mode()&0111 != 0 {
			mode = 0755
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		input, err := file.Open()
		if err != nil {
			output.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		inputErr := input.Close()
		outputErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if inputErr != nil {
			return inputErr
		}
		if outputErr != nil {
			return outputErr
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: modulearchive ZIP MODULE@VERSION H1 DESTINATION")
		os.Exit(2)
	}
	if err := extract(os.Args[1], os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
