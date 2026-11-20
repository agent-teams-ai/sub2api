package sysutil

import (
	"math"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/mem"
)

const cgroupRoot = "/sys/fs/cgroup"

// CgroupMemoryLimitBytes returns the smallest positive memory limit applying
// to the current process along its cgroup v1/v2 hierarchy (including parents).
// It returns 0 if the limit is unlimited or cannot be determined.
func CgroupMemoryLimitBytes() uint64 {
	return cgroupMemoryLimit(cgroupRoot, "/proc/self/cgroup")
}

// CgroupMemoryMountRootLimitBytes returns the cgroup mount-root memory limit
// in bytes for the selected hierarchy (v2=true, v1=false), or 0 when the
// root is unlimited or unavailable. Ops pairs this with mount-root usage,
// whereas process memory budgeting uses the potentially tighter child/parent
// cgroup limit from CgroupMemoryLimitBytes.
func CgroupMemoryMountRootLimitBytes(v2 bool) uint64 {
	return cgroupMemoryMountRootLimit(cgroupRoot, v2)
}

func cgroupMemoryMountRootLimit(root string, v2 bool) uint64 {
	if v2 {
		return cgroupPathMemoryLimit(root, "/", "memory.max")
	}
	return cgroupPathMemoryLimit(filepath.Join(root, "memory"), "/", "memory.limit_in_bytes")
}

// CgroupMemoryUsageAndLimitBytes returns paired usage and the tightest cgroup
// memory limit for the current process. Both values are read from the same
// hierarchy level; ok is false if the matching usage counter is unavailable.
func CgroupMemoryUsageAndLimitBytes() (usedBytes, totalBytes uint64, ok bool) {
	return cgroupMemoryUsageAndLimit(cgroupRoot, "/proc/self/cgroup")
}

type cgroupMemoryStats struct {
	used  uint64
	total uint64
	ok    bool
}

// cgroupMemoryUsageAndLimit selects the tightest positive limit in the v1/v2
// hierarchy and reads usage at precisely that level (a parent slice may have
// a tighter limit and include usage from other children). If the usage of the
// limiting level is missing, the pair is unavailable rather than mismatched.
func cgroupMemoryUsageAndLimit(root, selfCgroupFile string) (uint64, uint64, bool) {
	var selected cgroupMemoryStats
	consider := func(next cgroupMemoryStats) {
		if next.total > 0 && (selected.total == 0 || next.total < selected.total ||
			(next.total == selected.total && !selected.ok && next.ok)) {
			selected = next
		}
	}
	if raw, err := os.ReadFile(selfCgroupFile); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
			if len(fields) != 3 {
				continue
			}
			switch {
			case fields[1] == "":
				consider(cgroupPathMemoryStats(root, fields[2], "memory.max", "memory.current"))
			case slices.Contains(strings.Split(fields[1], ","), "memory"):
				consider(cgroupPathMemoryStats(filepath.Join(root, "memory"), fields[2], "memory.limit_in_bytes", "memory.usage_in_bytes"))
			}
		}
	}
	consider(cgroupPathMemoryStats(root, "/", "memory.max", "memory.current"))
	consider(cgroupPathMemoryStats(filepath.Join(root, "memory"), "/", "memory.limit_in_bytes", "memory.usage_in_bytes"))
	return selected.used, selected.total, selected.ok
}

func cgroupPathMemoryStats(mount, cgroupPath, limitFile, usageFile string) cgroupMemoryStats {
	mountRoot, err := os.OpenRoot(mount)
	if err != nil {
		return cgroupMemoryStats{}
	}
	defer func() { _ = mountRoot.Close() }()
	var out cgroupMemoryStats
	for dir := path.Clean("/" + cgroupPath); ; dir = path.Dir(dir) {
		rel := filepath.FromSlash(strings.TrimPrefix(dir, "/"))
		limit := readCgroupLimitFile(mountRoot, filepath.Join(rel, limitFile))
		if limit > 0 && (out.total == 0 || limit < out.total) {
			rawUsage, readErr := mountRoot.ReadFile(filepath.Join(rel, usageFile))
			used, parseErr := strconv.ParseUint(strings.TrimSpace(string(rawUsage)), 10, 64)
			out = cgroupMemoryStats{used: used, total: limit, ok: readErr == nil && parseErr == nil}
		}
		if dir == "/" {
			return out
		}
	}
}

// MemoryLimitBytes returns the memory available to this process: the smallest
// of physical memory, the cgroup (container/systemd) limit and GOMEMLIMIT.
// It returns 0 when none of them can be determined.
func MemoryLimitBytes() uint64 {
	var physical uint64
	if vm, err := mem.VirtualMemory(); err == nil {
		physical = vm.Total
	}
	goLimit := debug.SetMemoryLimit(-1)
	return minPositive(physical, CgroupMemoryLimitBytes(), goMemoryLimit(goLimit))
}

// cgroupMemoryLimit returns the tightest memory limit on this process's cgroup
// path, or 0 when unlimited or unavailable. A parent's limit applies to its
// children (e.g. a systemd slice), so every level up to the mount root is
// checked, for both the v2 unified hierarchy and the v1 memory controller.
func cgroupMemoryLimit(root, selfCgroupFile string) uint64 {
	var limit uint64
	if raw, err := os.ReadFile(selfCgroupFile); err == nil {
		// Each line is "hierarchy-ID:controller-list:cgroup-path".
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
			if len(fields) != 3 {
				continue
			}
			switch {
			case fields[1] == "":
				limit = minPositive(limit, cgroupPathMemoryLimit(root, fields[2], "memory.max"))
			case slices.Contains(strings.Split(fields[1], ","), "memory"):
				limit = minPositive(limit, cgroupPathMemoryLimit(filepath.Join(root, "memory"), fields[2], "memory.limit_in_bytes"))
			}
		}
	}
	// Mount roots cover an unreadable /proc/self/cgroup.
	limit = minPositive(limit, cgroupPathMemoryLimit(root, "/", "memory.max"))
	return minPositive(limit, cgroupPathMemoryLimit(filepath.Join(root, "memory"), "/", "memory.limit_in_bytes"))
}

// cgroupPathMemoryLimit walks from the cgroup up to the mount root. Levels not
// visible in this mount (e.g. a host path inside a container) are skipped.
// Reads go through os.Root, so a cgroup path from /proc/self/cgroup can never
// resolve outside the mount.
func cgroupPathMemoryLimit(mount, cgroupPath, limitFile string) uint64 {
	mountRoot, err := os.OpenRoot(mount)
	if err != nil {
		return 0
	}
	defer func() { _ = mountRoot.Close() }()
	var limit uint64
	for dir := path.Clean("/" + cgroupPath); ; dir = path.Dir(dir) {
		name := filepath.Join(filepath.FromSlash(strings.TrimPrefix(dir, "/")), limitFile)
		limit = minPositive(limit, readCgroupLimitFile(mountRoot, name))
		if dir == "/" {
			return limit
		}
	}
}

func readCgroupLimitFile(mountRoot *os.Root, name string) uint64 {
	raw, err := mountRoot.ReadFile(name)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	// v2 reports "max" when unlimited; v1 reports a page-rounded huge value.
	if err != nil || v >= 1<<60 {
		return 0
	}
	return v
}

func goMemoryLimit(limit int64) uint64 {
	if limit <= 0 || limit == math.MaxInt64 {
		return 0
	}
	return uint64(limit)
}

func minPositive(values ...uint64) uint64 {
	var out uint64
	for _, v := range values {
		if v > 0 && (out == 0 || v < out) {
			out = v
		}
	}
	return out
}
