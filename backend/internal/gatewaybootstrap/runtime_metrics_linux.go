//go:build linux

package gatewaybootstrap

import (
	"net/http"
	"runtime"
	"runtime/metrics"

	"github.com/gin-gonic/gin"
)

// nativeRuntimeSnapshot is the fixed GET /private/native/v1/runtime JSON contract
// for the C sampler. Counters are unsigned integers, numGoroutine is positive,
// and the fixed v2 extension adds a version string and consistency boolean.
//
// Exact keys and sources:
//
//	heapAllocBytes: runtime.MemStats.HeapAlloc, bytes of allocated heap objects.
//	heapInuseBytes: runtime.MemStats.HeapInuse, bytes in in-use heap spans.
//	sysBytes: runtime.MemStats.Sys, bytes obtained from the OS by the Go runtime.
//	numGC: runtime.MemStats.NumGC, completed GC cycles.
//	numGoroutine: runtime.NumGoroutine(), current Go goroutine count.
//
// This describes only the current native Go process. Sys is not RSS, cgroup
// memory, C memory or readiness. The memory snapshot and goroutine count are
// separate observations; callers must not infer an atomic cross-field instant.
type nativeRuntimeSnapshot struct {
	HeapAllocBytes       uint64 `json:"heapAllocBytes"`
	HeapInuseBytes       uint64 `json:"heapInuseBytes"`
	SysBytes             uint64 `json:"sysBytes"`
	NumGC                uint32 `json:"numGC"`
	NumGoroutine         int    `json:"numGoroutine"`
	MetricVersion        string `json:"metricVersion"`
	HeapLiveBytes        uint64 `json:"heapLiveBytes"`
	AutomaticGCCycles    uint64 `json:"automaticGCCycles"`
	ForcedGCCycles       uint64 `json:"forcedGCCycles"`
	GCSnapshotConsistent bool   `json:"gcSnapshotConsistent"`
}

// Equal completed-cycle counters bracket one previous-GC live observation.
// No retry or lower-value selection conceals a GC that completed mid-read.
func nativeNaturalGCConsistent(before, after runtime.MemStats, total, automatic, forced uint64) bool {
	return before.NumGC == after.NumGC && before.LastGC == after.LastGC &&
		uint64(before.NumGC) == total && before.NumForcedGC == after.NumForcedGC &&
		uint64(before.NumForcedGC) == forced && automatic <= total && forced == total-automatic
}

// nativeRuntime reads aggregate counters on demand. It does not force GC,
// retain samples, start polling, or inspect processes/files/configuration.
// Authorization and admission happen before this handler in privateHandler.
func nativeRuntime(c *gin.Context) {
	var before, memory runtime.MemStats
	runtime.ReadMemStats(&before)
	live := []metrics.Sample{{Name: "/gc/heap/live:bytes"}, {Name: "/gc/cycles/total:gc-cycles"},
		{Name: "/gc/cycles/automatic:gc-cycles"}, {Name: "/gc/cycles/forced:gc-cycles"}}
	metrics.Read(live)
	runtime.ReadMemStats(&memory)
	snapshot := nativeRuntimeSnapshot{
		HeapAllocBytes: memory.HeapAlloc,
		HeapInuseBytes: memory.HeapInuse,
		SysBytes:       memory.Sys,
		NumGC:          memory.NumGC,
		NumGoroutine:   runtime.NumGoroutine(),
		MetricVersion:  "natural_gc_live_v2",
	}
	// Preserve raw allocation counters even when a concurrent cycle makes the live observation unusable.
	kindsOK := true
	for _, sample := range live {
		kindsOK = kindsOK && sample.Value.Kind() == metrics.KindUint64
	}
	if kindsOK {
		snapshot.HeapLiveBytes = live[0].Value.Uint64()
		snapshot.AutomaticGCCycles = live[2].Value.Uint64()
		snapshot.ForcedGCCycles = live[3].Value.Uint64()
		snapshot.GCSnapshotConsistent = nativeNaturalGCConsistent(before, memory, live[1].Value.Uint64(), snapshot.AutomaticGCCycles, snapshot.ForcedGCCycles)
	}
	// An authenticated sample must never become a cached management response.
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, snapshot)
}
