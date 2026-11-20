package sysutil

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, file, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte(content), 0o600))
}

func TestCgroupMemoryLimit(t *testing.T) {
	t.Run("v2 namespaced root", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "0::/\n")
		writeFile(t, filepath.Join(root, "memory.max"), "4294967296\n")
		require.Equal(t, uint64(4<<30), cgroupMemoryLimit(root, self))
	})

	t.Run("v2 tightest limit along the path", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "0::/system.slice/sub2api.service\n")
		writeFile(t, filepath.Join(root, "memory.max"), "max\n")
		writeFile(t, filepath.Join(root, "system.slice", "memory.max"), "8589934592\n")
		writeFile(t, filepath.Join(root, "system.slice", "sub2api.service", "memory.max"), "max\n")
		require.Equal(t, uint64(8<<30), cgroupMemoryLimit(root, self))
	})

	t.Run("v2 unlimited", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "0::/\n")
		writeFile(t, filepath.Join(root, "memory.max"), "max\n")
		require.Zero(t, cgroupMemoryLimit(root, self))
	})

	t.Run("v1 limit and unlimited sentinel", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "missing")
		writeFile(t, filepath.Join(root, "memory", "memory.limit_in_bytes"), "2147483648\n")
		require.Equal(t, uint64(2<<30), cgroupMemoryLimit(root, self))

		writeFile(t, filepath.Join(root, "memory", "memory.limit_in_bytes"), "9223372036854771712\n")
		require.Zero(t, cgroupMemoryLimit(root, self))
	})

	t.Run("v1 tightest limit along the memory controller path", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "12:pids:/system.slice/sub2api.service\n9:memory:/system.slice/sub2api.service\n1:name=systemd:/system.slice/sub2api.service\n0::/system.slice/sub2api.service\n")
		writeFile(t, filepath.Join(root, "memory", "memory.limit_in_bytes"), "9223372036854771712\n")
		writeFile(t, filepath.Join(root, "memory", "system.slice", "memory.limit_in_bytes"), "9223372036854771712\n")
		writeFile(t, filepath.Join(root, "memory", "system.slice", "sub2api.service", "memory.limit_in_bytes"), "4294967296\n")
		require.Equal(t, uint64(4<<30), cgroupMemoryLimit(root, self))
	})

	t.Run("v1 combined controller list", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "5:cpuset,memory:/app\n")
		writeFile(t, filepath.Join(root, "memory", "app", "memory.limit_in_bytes"), "3221225472\n")
		require.Equal(t, uint64(3<<30), cgroupMemoryLimit(root, self))
	})

	t.Run("host path not visible in container mount falls back to root", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "9:memory:/docker/abc\n")
		writeFile(t, filepath.Join(root, "memory", "memory.limit_in_bytes"), "2147483648\n")
		require.Equal(t, uint64(2<<30), cgroupMemoryLimit(root, self))
	})

	t.Run("cgroup path cannot escape the mount", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "cgroup")
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, filepath.Join(parent, "outside", "memory.max"), "1073741824\n")
		writeFile(t, filepath.Join(root, "memory.max"), "max\n")
		require.NoError(t, os.Symlink(filepath.Join(parent, "outside"), filepath.Join(root, "link")))

		writeFile(t, self, "0::/../outside\n")
		require.Zero(t, cgroupMemoryLimit(root, self))

		writeFile(t, self, "0::/link\n")
		require.Zero(t, cgroupMemoryLimit(root, self))
	})

	t.Run("unavailable", func(t *testing.T) {
		require.Zero(t, cgroupMemoryLimit(t.TempDir(), filepath.Join(t.TempDir(), "missing")))
	})
}

func TestCgroupMemoryMountRootLimitPairsWithRootUsage(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(t.TempDir(), "cgroup")
	writeFile(t, self, "0::/system.slice/app\n")
	writeFile(t, filepath.Join(root, "memory.max"), "8589934592\n")
	writeFile(t, filepath.Join(root, "system.slice", "memory.max"), "2147483648\n")
	require.Equal(t, uint64(2<<30), cgroupMemoryLimit(root, self),
		"process budget should respect the tighter nested slice")
	require.Equal(t, uint64(8<<30), cgroupMemoryMountRootLimit(root, true),
		"mount-root usage must be compared with the mount-root limit")

	writeFile(t, filepath.Join(root, "memory", "memory.limit_in_bytes"), "4294967296\n")
	writeFile(t, filepath.Join(root, "memory", "system.slice", "memory.limit_in_bytes"), "1073741824\n")
	require.Equal(t, uint64(4<<30), cgroupMemoryMountRootLimit(root, false),
		"v1 usage must be compared with its own hierarchy root limit")

	writeFile(t, filepath.Join(root, "memory.max"), "max\n")
	require.Zero(t, cgroupMemoryMountRootLimit(root, true),
		"unlimited roots must fall back to coherent host metrics")
}

func TestGoMemoryLimit(t *testing.T) {
	require.Zero(t, goMemoryLimit(math.MaxInt64))
	require.Equal(t, uint64(1<<30), goMemoryLimit(1<<30))
}

func TestMinPositive(t *testing.T) {
	require.Zero(t, minPositive(0, 0))
	require.Equal(t, uint64(3), minPositive(0, 5, 3, 0))
}

func TestCgroupMemoryUsageAndLimit(t *testing.T) {
	t.Run("v2 uses the limiting parent usage", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "0::/system.slice/sub2api.service\n")
		writeFile(t, filepath.Join(root, "memory.max"), "1073741824\n")
		writeFile(t, filepath.Join(root, "memory.current"), "805306368\n")
		writeFile(t, filepath.Join(root, "system.slice", "memory.max"), "536870912\n")
		writeFile(t, filepath.Join(root, "system.slice", "memory.current"), "402653184\n")
		writeFile(t, filepath.Join(root, "system.slice", "sub2api.service", "memory.max"), "max\n")
		writeFile(t, filepath.Join(root, "system.slice", "sub2api.service", "memory.current"), "1048576\n")
		used, total, ok := cgroupMemoryUsageAndLimit(root, self)
		require.True(t, ok)
		require.Equal(t, uint64(384<<20), used)
		require.Equal(t, uint64(512<<20), total)
	})
	t.Run("v1 avoids combining host usage with child limit", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "4:memory:/system.slice/sub2api.service\n")
		writeFile(t, filepath.Join(root, "memory", "memory.limit_in_bytes"), "1073741824\n")
		writeFile(t, filepath.Join(root, "memory", "memory.usage_in_bytes"), "805306368\n")
		writeFile(t, filepath.Join(root, "memory", "system.slice", "memory.limit_in_bytes"), "536870912\n")
		writeFile(t, filepath.Join(root, "memory", "system.slice", "memory.usage_in_bytes"), "402653184\n")
		writeFile(t, filepath.Join(root, "memory", "system.slice", "sub2api.service", "memory.limit_in_bytes"), "268435456\n")
		writeFile(t, filepath.Join(root, "memory", "system.slice", "sub2api.service", "memory.usage_in_bytes"), "134217728\n")
		used, total, ok := cgroupMemoryUsageAndLimit(root, self)
		require.True(t, ok)
		require.Equal(t, uint64(128<<20), used)
		require.Equal(t, uint64(256<<20), total)
	})
	t.Run("missing usage for tightest limit cannot claim a valid pair", func(t *testing.T) {
		root := t.TempDir()
		self := filepath.Join(t.TempDir(), "cgroup")
		writeFile(t, self, "0::/child\n")
		writeFile(t, filepath.Join(root, "memory.max"), "1073741824\n")
		writeFile(t, filepath.Join(root, "memory.current"), "805306368\n")
		writeFile(t, filepath.Join(root, "child", "memory.max"), "268435456\n")
		_, total, ok := cgroupMemoryUsageAndLimit(root, self)
		require.False(t, ok)
		require.Equal(t, uint64(256<<20), total)
	})
}
