package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedArchiveExtraction(t *testing.T) {
	const prefix = "example.test/module@v1.0.0"
	const checksum = "h1:EumcPKfhFDWc+Che36Q2DBzmIn3RKq79Jw8JDP4rZ5M="
	for _, test := range []struct {
		name, path, content string
		valid               bool
	}{
		{"original", prefix + "/source.go", "package fixture\n", true},
		{"modified bytes", prefix + "/source.go", "package modified\n", false},
		{"unexpected prefix", "other/source.go", "package fixture\n", false},
		{"escaping path", prefix + "/../source.go", "package fixture\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "module.zip")
			file, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(file)
			entry, err := writer.Create(test.path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = entry.Write([]byte(test.content)); err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(root, "extracted")
			err = extract(archive, prefix, checksum, destination)
			if !test.valid {
				if err == nil {
					t.Fatal("unverified archive accepted")
				}
				if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
					t.Fatal("wrote source before archive verification")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(filepath.Join(destination, "source.go"))
			if err != nil || string(content) != test.content {
				t.Fatal("verified source not extracted")
			}
		})
	}
}
