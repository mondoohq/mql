// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"strings"
)

// PyTorchHubDetector discovers models cached by PyTorch Hub
// (~/.cache/torch/hub/checkpoints). These are typically .pth or .pt weight
// files. The trailing hex hash is stripped from the filename to produce
// a clean model name (e.g. "resnet50-0676ba61.pth" -> "resnet50").
type PyTorchHubDetector struct{}

func (d *PyTorchHubDetector) Detect(ctx DetectContext) []ModelInfo {
	checkpointsDir := joinPath(ctx.Home, ".cache", "torch", "hub", "checkpoints")
	entries, err := ctx.Fs.ReadDir(checkpointsDir)
	if err != nil {
		return nil
	}

	var results []ModelInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		lower := strings.ToLower(e.Name())
		if !strings.HasSuffix(lower, ".pth") && !strings.HasSuffix(lower, ".pt") {
			continue
		}

		name := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".pth"), ".pt")
		// Strip trailing hash: resnet50-0676ba61 -> resnet50
		if idx := strings.LastIndex(name, "-"); idx > 0 {
			candidate := name[idx+1:]
			if len(candidate) >= 6 && isHex(candidate) {
				name = name[:idx]
			}
		}

		results = append(results, ModelInfo{
			Name:       name,
			Source:     "pytorch",
			Path:       joinPath(checkpointsDir, e.Name()),
			Size:       e.Size(),
			ModifiedAt: e.ModTime(),
			Format:     "pytorch",
		})
	}
	return results
}
