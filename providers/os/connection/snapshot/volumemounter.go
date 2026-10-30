// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package snapshot

import (
	"maps"
	"os"
	"slices"
	"sort"
	"strings"

	"go.mondoo.com/mql/utils/stringx"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

const (
	NoSetup = "no-setup"
	IsSetup = "is-setup"
)

//go:generate mockgen -source=./volumemounter.go -destination=./mock_volumemounter.go -package=snapshot
type VolumeMounter interface {
	Mount(input *MountPartitionInput) (*MountedPartition, error)
	Umount(partition *MountedPartition) error
	UnmountAll() error
	RemoveTempScanDir() error
}

type volumeMounter struct {
	// the tmp dirs we create; serves as the directory we mount the volumes to
	// maps directory name to the partition name
	scanDirs  map[string]string
	cmdRunner *LocalCommandRunner
}

func NewVolumeMounter(shell []string) VolumeMounter {
	return &volumeMounter{
		cmdRunner: &LocalCommandRunner{Shell: shell},
		scanDirs:  make(map[string]string),
	}
}

// Mounts a specific partition and returns the directory it was mounted to
func (m *volumeMounter) Mount(input *MountPartitionInput) (*MountedPartition, error) {
	if input == nil {
		return nil, errors.New("mount device> partition is required")
	}
	if input.Partition.Name == "" {
		return nil, errors.New("mount device> partition name is required")
	}
	if input.Partition.FsType == "" {
		return nil, errors.New("mount device> partition fs type is required")
	}

	mountDir := input.MountDir
	if mountDir == "" {
		dir, err := m.createScanDir()
		if err != nil {
			return nil, err
		}
		mountDir = dir
	}

	m.scanDirs[mountDir] = input.Partition.Name

	mp := &MountedPartition{
		Partition:    input.Partition,
		MountOptions: input.MountOptions,
		MountPoint:   mountDir,
	}
	return mp, m.mountVolume(input, mountDir)
}

func (m *volumeMounter) Umount(partition *MountedPartition) error {
	if partition == nil {
		return errors.New("unmount device> partition is required")
	}
	if partition.Partition.Name == "" {
		return errors.New("unmount device> partition name is required")
	}
	log.Debug().Str("dir", partition.MountPoint).Str("name", partition.Partition.Name).Msg("unmount volume")
	if err := Unmount(partition.MountPoint); err != nil {
		log.Warn().Err(err).Str("dir", partition.MountPoint).Msg("failed to unmount dir")
		return err
	}
	delete(m.scanDirs, partition.MountPoint)

	return nil
}

func (m *volumeMounter) createScanDir() (string, error) {
	dir, err := os.MkdirTemp("", "cnspec-scan")
	if err != nil {
		log.Error().Err(err).Msg("error creating directory")
		return "", err
	}
	log.Debug().Str("dir", dir).Msg("created tmp scan dir")
	return dir, nil
}

func (m *volumeMounter) mountVolume(input *MountPartitionInput, dir string) error {
	opts := input.MountOptions
	fsType := input.Partition.FsType
	name := input.Partition.Name
	if fsType == "xfs" {
		opts = append(opts, "nouuid")
	}

	opts = stringx.DedupStringArray(opts)
	opts = sanitizeOptions(opts)

	log.Debug().Str("fstype", fsType).Str("device", name).Str("dir", dir).Strs("opts", opts).Msg("mount volume to scan dir")
	return Mount(name, dir, fsType, opts)
}

func sanitizeOptions(options []string) []string {
	sanitized := make([]string, 0)
	for _, opt := range options {
		switch {
		case opt == "defaults":
			continue
		case strings.HasPrefix(opt, "x-systemd"):
			continue
		default:
			sanitized = append(sanitized, opt)
		}
	}
	return sanitized
}

func (m *volumeMounter) UnmountAll() error {
	if len(m.scanDirs) == 0 {
		log.Warn().Msg("no scan dirs to unmount, skipping")
		return nil
	}

	var errs []error
	dirs := slices.Collect(maps.Keys(m.scanDirs))
	// sort the entries by the length of the mountpoint, so we can mount the deepest directories first
	sort.Slice(dirs, func(i, j int) bool {
		return PathDepth(dirs[i]) > PathDepth(dirs[j])
	})
	for _, dir := range dirs {
		log.Debug().
			Str("dir", dir).
			Str("partition", m.scanDirs[dir]).
			Msg("unmount volume")
		if err := Unmount(dir); err != nil {
			log.Warn().
				Str("dir", dir).
				Err(err).Msg("failed to unmount dir")
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *volumeMounter) RemoveTempScanDir() error {
	var errs []error
	for dir, partition := range m.scanDirs {
		log.Debug().
			Str("dir", dir).
			Str("partition", partition).
			Msg("remove created dir")
		if err := os.RemoveAll(dir); err != nil {
			log.Error().Err(err).
				Str("dir", dir).
				Msg("failed to remove dir")
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func PathDepth(path string) int {
	if path == "/" {
		return 0
	}
	return len(strings.Split(strings.Trim(path, "/"), "/"))
}
