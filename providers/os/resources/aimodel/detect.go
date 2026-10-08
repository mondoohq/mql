// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/afero"
)

// joinPath joins path elements in the style of the target that base belongs
// to. filepath.Join follows the host mql runs on instead, so scanning Windows
// from macOS reported C:\Users\me/.cache/huggingface/hub, and scanning Linux
// from Windows would turn every slash into a backslash. A base with a drive
// letter or a UNC prefix is a Windows path and is joined with backslashes,
// normalizing any slash already in it; anything else is joined with slashes.
// base must not be empty: like filepath.Join, an empty base yields a relative
// path, and every detector starts from a user home or a resolved store.
func joinPath(base string, elem ...string) string {
	if !isWindowsPath(base) {
		return path.Join(append([]string{base}, elem...)...)
	}

	parts := []string{}
	for _, p := range append([]string{base}, elem...) {
		parts = append(parts, strings.FieldsFunc(p, isPathSeparator)...)
	}
	joined := strings.Join(parts, `\`)
	if strings.HasPrefix(base, `\\`) {
		return `\\` + joined
	}
	return joined
}

// baseName is the last element of p, split on both separators so that a
// Windows path reads the same on every host.
func baseName(p string) string {
	if i := strings.LastIndexFunc(p, isPathSeparator); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isWindowsPath(p string) bool {
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 2 && p[1] == ':' &&
		(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z')
}

func isPathSeparator(r rune) bool {
	return r == '/' || r == '\\'
}

// ModelInfo holds the metadata for a single discovered AI model cache entry.
// Each detector populates what it can; fields left empty mean the source
// doesn't provide that information.
type ModelInfo struct {
	Name          string
	Source        string
	Vendor        string
	Family        string
	Path          string
	Size          int64
	ModifiedAt    time.Time
	Format        string
	Version       string
	Quantization  string
	ParameterSize string
	Architecture  string
	License       string
	Tags          []string
	Description   string
}

// DetectContext carries the shared state needed by every detector.
type DetectContext struct {
	Fs       *afero.Afero
	Home     string
	OSFamily string
	// OllamaModelsDirs are the Ollama model stores to read, resolved from the
	// server's configuration. Empty falls back to $HOME/.ollama/models, which
	// is only correct when nothing relocated the store.
	OllamaModelsDirs []string
}

// Detector discovers locally cached AI models from a single source.
type Detector interface {
	Detect(ctx DetectContext) []ModelInfo
}

var (
	reQuantization = regexp.MustCompile(`(?i)(I?Q[0-9]+_[A-Z0-9_]+|BF16|F16|F32|FP16|FP32)`)
	// A parameter count in billions (b) or millions (m), such as the "7b" of
	// "llama3:7b" or the "135m" of "smollm:135m". The leading separator (dash,
	// underscore, colon, space) avoids matching the letter inside words.
	reParamSize = regexp.MustCompile(`(?i)[-_: ](\d+\.?\d*)([bm])(?:[-_. ]|$)`)
)

// Detectors returns all registered model detectors.
func Detectors() []Detector {
	return []Detector{
		&OllamaDetector{},
		&HuggingFaceDetector{},
		&LMStudioDetector{},
		&GPT4AllDetector{},
		&PyTorchHubDetector{},
		&KerasDetector{},
		&TFHubDetector{},
		&JanDetector{},
		&ChromeDetector{},
	}
}

// DetectAll runs every detector against each user home and returns the
// combined results. Resolved Ollama stores already include every user's own
// store besides the daemon's, so Ollama reads them once, which also keeps one
// model reachable through two stores a single model. A model is reported once
// per source and path, however many homes lead to it.
func DetectAll(afs *afero.Afero, homes []string, osFamily string, ollamaModelsDirs []string) []ModelInfo {
	var all []ModelInfo
	seen := map[string]struct{}{}
	add := func(models []ModelInfo) {
		for _, m := range models {
			key := m.Source + "\x00" + m.Path
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			all = append(all, m)
		}
	}

	for _, d := range Detectors() {
		if _, ok := d.(*OllamaDetector); ok && len(ollamaModelsDirs) > 0 {
			add(d.Detect(DetectContext{Fs: afs, OSFamily: osFamily, OllamaModelsDirs: ollamaModelsDirs}))
			continue
		}
		for _, home := range homes {
			add(d.Detect(DetectContext{Fs: afs, Home: home, OSFamily: osFamily}))
		}
	}
	return all
}

// --- Helpers ---

func dirSizeAndLatestMtime(afs *afero.Afero, dir string) (int64, time.Time) {
	var totalSize int64
	var latest time.Time
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return 0, latest
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".lock") {
			continue
		}
		totalSize += e.Size()
		if e.ModTime().After(latest) {
			latest = e.ModTime()
		}
	}
	return totalSize, latest
}

func dirSizeRecursive(afs *afero.Afero, dir string) (int64, time.Time) {
	var totalSize int64
	var latest time.Time
	_ = afero.Walk(afs, dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		totalSize += info.Size()
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return totalSize, latest
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
