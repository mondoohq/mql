// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpinstancesnapshot

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/id/gce"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v2"
	"google.golang.org/api/option"
)

const (
	createdByLabel = "created-by"
	createdValue   = "cnspec"

	// zoneOperationTimeout caps how long we wait for a single zonal operation.
	// Snapshotting a large disk is slow, so this is a backstop against an
	// operation that never reaches DONE, not a target duration.
	zoneOperationTimeout = 30 * time.Minute
)

// invalidDiskNameChars matches any character that is not allowed in a GCP disk
// name (i.e. anything outside [a-z0-9-]).
var invalidDiskNameChars = regexp.MustCompile(`[^a-z0-9-]`)

func NewInstanceUrl(projectID, zone, instanceName string) string {
	return fmt.Sprintf(
		"projects/%s/zones/%s/instances/%s", projectID, zone, instanceName,
	)
}

func NewSourceDiskUrl(projectID, zone, diskName string) string {
	return fmt.Sprintf(
		"projects/%s/zones/%s/disks/%s", projectID, zone, diskName,
	)
}

// newDiskName builds a GCP-compliant temporary disk name for the scanner's
// clone/snapshot disk. See buildDiskName.
func newDiskName(instanceName string) string {
	return buildDiskName(instanceName, time.Now())
}

// buildDiskName produces a name matching GCP's rule
// [a-z]([-a-z0-9]{0,61}[a-z0-9])? with a max length of 63. It lowercases and
// replaces invalid characters in the instance name and truncates it so the
// full "cnspec-<instance>-<timestamp>" name fits.
func buildDiskName(instanceName string, t time.Time) string {
	prefix := "cnspec-"
	timestamp := t.Format("20060102t150405") // 15 chars, all valid characters

	// sanitize the instance name: lowercase, and replace any character that is
	// not in [a-z0-9-] with '-'
	sanitized := invalidDiskNameChars.ReplaceAllString(strings.ToLower(instanceName), "-")

	// reserve room for the prefix and the "-"+timestamp suffix, then truncate
	// the sanitized instance name so the assembled name fits within 63 chars
	avail := max(63-len(prefix)-1-len(timestamp), 0)
	if len(sanitized) > avail {
		sanitized = sanitized[:avail]
	}

	// trim trailing '-' from the (possibly truncated) instance name so the
	// assembled name reads cleanly
	sanitized = strings.TrimRight(sanitized, "-")

	// if nothing usable remains, drop the separator to avoid a double dash
	if sanitized == "" {
		return prefix + timestamp
	}

	// the timestamp always ends in a digit, so the assembled name ends in
	// [a-z0-9] and starts with the "cnspec-" prefix (a letter) — both required
	// by GCP's rule
	return prefix + sanitized + "-" + timestamp
}

func NewSnapshotCreator() (*SnapshotCreator, error) {
	scope := []string{cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope}
	client, err := googleoauth.DefaultClient(context.Background(), scope...)
	if err != nil {
		return nil, err
	}

	sc := &SnapshotCreator{
		client: client,
		labels: map[string]string{
			createdByLabel: createdValue,
		},
	}
	return sc, nil
}

type SnapshotCreator struct {
	client *http.Client
	labels map[string]string
}

// computeService returns a new Compute Service instance
func (sc *SnapshotCreator) computeServiceClient(ctx context.Context) (*compute.Service, error) {
	return compute.NewService(ctx, option.WithHTTPClient(sc.client))
}

type instanceInfo struct {
	PlatformMrn       string
	ProjectID         string
	Zone              string
	InstanceName      string
	BootDiskSourceURL string
}

func (sc *SnapshotCreator) InstanceInfo(projectID, zone, instanceName string) (instanceInfo, error) {
	ctx := context.Background()
	ii := instanceInfo{}

	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return ii, err
	}

	instance, err := computeService.Instances.Get(projectID, zone, instanceName).Context(ctx).Do()
	if err != nil {
		return ii, err
	}

	ii.ProjectID = projectID
	ii.Zone = zone
	ii.InstanceName = instance.Name
	ii.PlatformMrn = gce.MondooGcpInstancePlatformMrn(projectID, zone, instance.Name)

	// search for boot disk
	var bootDisk *compute.AttachedDisk
	for i := range instance.Disks {
		dsk := instance.Disks[i]
		if dsk.Boot {
			bootDisk = dsk
			break
		}
	}

	if bootDisk != nil {
		ii.BootDiskSourceURL = bootDisk.Source
	}

	return ii, nil
}

type snapshotInfo struct {
	PlatformMrn  string
	ProjectID    string
	SnapshotName string
	SnapshotUrl  string
}

func (sc *SnapshotCreator) SnapshotInfo(projectID, snapshotName string) (snapshotInfo, error) {
	ctx := context.Background()
	si := snapshotInfo{}

	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return si, err
	}

	snapshot, err := computeService.Snapshots.Get(projectID, snapshotName).Context(ctx).Do()
	if err != nil {
		return si, err
	}

	si.ProjectID = projectID
	si.SnapshotName = snapshot.Name
	si.SnapshotUrl = snapshot.SelfLink
	si.PlatformMrn = SnapshotPlatformMrn(projectID, snapshot.Name)

	return si, nil
}

// searchLatestSnapshot looks for the latest available snapshot for the instance
func (sc *SnapshotCreator) searchLatestSnapshot(projectID, sourceDiskUrl string) (string, time.Time, error) {
	ctx := context.Background()
	latestSnapshotTimestamp := time.UnixMilli(0)

	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return "", latestSnapshotTimestamp, err
	}

	var latestSnapshot *compute.Snapshot

	req := computeService.Snapshots.List(projectID)
	if err := req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			// we are only interested in disks that are attached to the
			if snapshot.SourceDisk != sourceDiskUrl {
				continue
			}

			// RFC3339 encoded like 2021-02-28T02:31:38.654-08:00
			snapshotCreated, err := time.Parse(time.RFC3339, snapshot.CreationTimestamp)
			if err != nil {
				log.Err(err).Str("snapshot", snapshot.Name).Str("creation-timestamp", snapshot.CreationTimestamp).Msg("snapshot timestamp is not parsable")
				// we ignore snapshots that we cannot parse
				continue
			}

			if latestSnapshotTimestamp.Before(snapshotCreated) {
				latestSnapshot = snapshot
				latestSnapshotTimestamp = snapshotCreated
			}
		}
		return nil
	}); err != nil {
		return "", latestSnapshotTimestamp, err
	}

	if latestSnapshot == nil {
		return "", latestSnapshotTimestamp, status.Error(codes.NotFound, "no snapshot found")
	}

	return latestSnapshot.SelfLink, latestSnapshotTimestamp, nil
}

// createDisk creates a new disk
func (sc *SnapshotCreator) createDisk(disk *compute.Disk, projectID, zone, diskName string) (string, error) {
	var clonedDiskUrl string
	ctx := context.Background()

	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return "", err
	}

	op, err := computeService.Disks.Insert(projectID, zone, disk).Context(ctx).Do()
	if err != nil {
		return clonedDiskUrl, err
	}

	// wait for the disk creation operation to complete
	operation, err := sc.waitForZoneOperation(ctx, computeService, projectID, zone, op.Name, "create disk")
	if err != nil {
		return clonedDiskUrl, err
	}

	return operation.TargetLink, nil
}

// createSnapshotDisk creates a new disk from a snapshot
func (sc *SnapshotCreator) createSnapshotDisk(snapshotUrl, projectID, zone, diskName string) (string, error) {
	// create a new disk from snapshot
	disk := &compute.Disk{
		Name:           diskName,
		SourceSnapshot: snapshotUrl,
		Labels:         sc.labels,
	}
	return sc.createDisk(disk, projectID, zone, diskName)
}

// isCrossZoneClone reports whether the source disk lives in a different zone
// than the target. A zonal disk can only be cloned directly within its own
// zone, so a cross-zone clone has to be bridged through a snapshot.
func isCrossZoneClone(sourceDisk, targetZone string) bool {
	_, srcZone, _, err := parseDiskUrl(sourceDisk)
	return err == nil && srcZone != "" && srcZone != targetZone
}

// cloneDisk clones a provided disk
func (sc *SnapshotCreator) cloneDisk(sourceDisk, projectID, zone, diskName string) (string, error) {
	// A zonal disk can only be cloned directly within the same zone. If the
	// source disk lives in a different zone than the target, bridge through a
	// temporary snapshot (snapshots are global) so cross-zone scanning works.
	if isCrossZoneClone(sourceDisk, zone) {
		return sc.cloneDiskViaSnapshot(sourceDisk, projectID, zone, diskName)
	}

	// create a new disk clone
	disk := &compute.Disk{
		Name:       diskName,
		SourceDisk: sourceDisk,
		Labels:     sc.labels,
	}
	return sc.createDisk(disk, projectID, zone, diskName)
}

// cloneDiskViaSnapshot clones a disk across zones by bridging through a
// temporary global snapshot. GCP requires the source disk and the target disk
// to be in the same zone for a direct disk clone, so when the scanner zone
// differs from the source disk's zone we first snapshot the source disk
// (snapshots are a global resource), create the scanner disk from that
// snapshot, and best-effort delete the temporary snapshot afterwards.
func (sc *SnapshotCreator) cloneDiskViaSnapshot(sourceDisk, projectID, zone, diskName string) (string, error) {
	ctx := context.Background()

	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return "", err
	}

	srcProject, srcZone, srcDiskName, err := parseDiskUrl(sourceDisk)
	if err != nil {
		return "", err
	}

	// build a valid temporary snapshot name. GCP requires names to match
	// [a-z]([-a-z0-9]{0,61}[a-z0-9])? and be at most 63 characters. The disk
	// name we are handed already follows this convention, so derive from it and
	// truncate to stay within the limit.
	snapName := diskName
	if len(snapName) > 63 {
		snapName = snapName[:63]
	}
	// avoid a trailing hyphen after truncation, which is invalid
	snapName = strings.TrimRight(snapName, "-")

	// create a snapshot from the source disk in the source project/zone
	op, err := computeService.Disks.CreateSnapshot(srcProject, srcZone, srcDiskName, &compute.Snapshot{
		Name:   snapName,
		Labels: sc.labels,
	}).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	// From here the snapshot may exist, so clean it up on every exit path, not
	// just the successful one. The scanner disk is independent of the snapshot
	// once created: GCP guarantees that deleting a snapshot does not affect
	// disks already created from it.
	defer func() {
		delOp, delErr := computeService.Snapshots.Delete(srcProject, snapName).Context(ctx).Do()
		if delErr != nil {
			log.Warn().Err(delErr).Str("snapshot", snapName).Msg("could not delete temporary snapshot created for cross-zone clone")
			return
		}
		// the API has accepted the delete; we deliberately do not wait for the
		// operation to finish, so log its name to keep it traceable.
		log.Debug().Str("snapshot", snapName).Str("operation", delOp.Name).Msg("deleting temporary snapshot created for cross-zone clone")
	}()

	if _, err := sc.waitForZoneOperation(ctx, computeService, srcProject, srcZone, op.Name, "create snapshot"); err != nil {
		return "", err
	}

	// fetch the snapshot to get its SelfLink, which is required to create a disk
	snap, err := computeService.Snapshots.Get(srcProject, snapName).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	// create the scanner disk from the snapshot in the target project/zone
	return sc.createSnapshotDisk(snap.SelfLink, projectID, zone, diskName)
}

// waitForZoneOperation blocks until the given zonal operation reaches the DONE
// state and returns it, or returns an error if the operation reported one or
// did not finish within zoneOperationTimeout.
func (sc *SnapshotCreator) waitForZoneOperation(ctx context.Context, computeService *compute.Service, projectID, zone, opName, action string) (*compute.Operation, error) {
	ctx, cancel := context.WithTimeout(ctx, zoneOperationTimeout)
	defer cancel()

	for {
		// Wait blocks server-side for up to two minutes, so a slow operation
		// costs a couple of requests instead of thousands of polls. It is
		// best-effort and may return before the operation is DONE, hence the loop.
		operation, err := computeService.ZoneOperations.Wait(projectID, zone, opName).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		if operation.Status == "DONE" {
			if operation.Error != nil {
				errMessage, _ := operation.Error.MarshalJSON()
				log.Debug().Str("error", string(errMessage)).Msg("operation failed")
				if len(operation.Error.Errors) > 0 {
					errMessage = []byte(operation.Error.Errors[0].Message)
				}
				return nil, fmt.Errorf("%s failed: %s", action, errMessage)
			}
			return operation, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s did not complete: %w", action, err)
		}
	}
}

// attachDisk attaches a disk to an instance
func (sc *SnapshotCreator) attachDisk(projectID, zone, instanceName, sourceDiskUrl, deviceName string) error {
	ctx := context.Background()

	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return err
	}

	// define the attached disk
	attachedDisk := &compute.AttachedDisk{
		Source:     sourceDiskUrl,
		DeviceName: deviceName,
	}

	// attach the disk to the instance
	op, err := computeService.Instances.AttachDisk(projectID, zone, instanceName, attachedDisk).Context(ctx).Do()
	if err != nil {
		return err
	}
	// wait for the operation to complete
	if _, err := sc.waitForZoneOperation(ctx, computeService, projectID, zone, op.Name, "attach disk"); err != nil {
		return err
	}

	return nil
}

func (sc *SnapshotCreator) detachDisk(projectID, zone, instanceName, deviceName string) error {
	ctx := context.Background()
	log.Debug().Str("device-name", deviceName).Msg("detach disk")
	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return err
	}

	// detach the disk from the instance
	op, err := computeService.Instances.DetachDisk(projectID, zone, instanceName, deviceName).Context(ctx).Do()
	if err != nil {
		return err
	}

	// wait for the operation to complete
	if _, err := sc.waitForZoneOperation(ctx, computeService, projectID, zone, op.Name, "detach disk"); err != nil {
		return err
	}

	return nil
}

// parseDiskUrl parses a provided GCP Disk URL
func parseDiskUrl(diskURL string) (string, string, string, error) {
	url, err := url.Parse(diskURL)
	if err != nil {
		return "", "", "", err
	}

	// extract the path and split it into components
	pathComponents := strings.Split(url.Path, "/")

	// the path we expect is
	// /compute/v1/projects/<project>/zones/<zone>/disks/<disk>. url.Parse
	// accepts almost anything, so guard the indexes here: without this a disk
	// url in an unexpected shape panics and takes the whole scan down.
	if len(pathComponents) < 9 {
		return "", "", "", fmt.Errorf("unexpected gcp disk url: %q", diskURL)
	}

	// extract project, zone, and disk names
	projectId := pathComponents[4]
	zone := pathComponents[6]
	disk := pathComponents[8]
	return projectId, zone, disk, nil
}

// deleteCreatedDisk deletes the given disk if it matches the created label
func (sc *SnapshotCreator) deleteCreatedDisk(diskUrl string) error {
	ctx := context.Background()

	computeService, err := sc.computeServiceClient(ctx)
	if err != nil {
		return err
	}

	projectID, zone, diskName, err := parseDiskUrl(diskUrl)
	if err != nil {
		return err
	}

	// attach the disk to the instance
	disk, err := computeService.Disks.Get(projectID, zone, diskName).Context(ctx).Do()
	if err != nil {
		return err
	}

	// only delete the volume if we created it, e.g., if we're scanning a snapshot
	if val, ok := disk.Labels[createdByLabel]; ok && val == createdValue {
		_, err := computeService.Disks.Delete(projectID, zone, diskName).Context(ctx).Do()
		if err != nil {
			return err
		}
		log.Debug().Str("disk", diskName).Msg("deleted temporary disk created by cnspec")
	} else {
		log.Debug().Str("disk", diskName).Msg("skipping disk deletion, not created by cnspec")
	}

	return nil
}
