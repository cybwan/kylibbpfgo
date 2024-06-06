package kylibbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"syscall"
)

//
// MapType
//

type MapType uint32

const (
	MapTypeUnspec              MapType = C.BPF_MAP_TYPE_UNSPEC
	MapTypeHash                MapType = C.BPF_MAP_TYPE_HASH
	MapTypeArray               MapType = C.BPF_MAP_TYPE_ARRAY
	MapTypeProgArray           MapType = C.BPF_MAP_TYPE_PROG_ARRAY
	MapTypePerfEventArray      MapType = C.BPF_MAP_TYPE_PERF_EVENT_ARRAY
	MapTypePerCPUHash          MapType = C.BPF_MAP_TYPE_PERCPU_HASH
	MapTypePerCPUArray         MapType = C.BPF_MAP_TYPE_PERCPU_ARRAY
	MapTypeStackTrace          MapType = C.BPF_MAP_TYPE_STACK_TRACE
	MapTypeCgroupArray         MapType = C.BPF_MAP_TYPE_CGROUP_ARRAY
	MapTypeLRUHash             MapType = C.BPF_MAP_TYPE_LRU_HASH
	MapTypeLRUPerCPUHash       MapType = C.BPF_MAP_TYPE_LRU_PERCPU_HASH
	MapTypeLPMTrie             MapType = C.BPF_MAP_TYPE_LPM_TRIE
	MapTypeArrayOfMaps         MapType = C.BPF_MAP_TYPE_ARRAY_OF_MAPS
	MapTypeHashOfMaps          MapType = C.BPF_MAP_TYPE_HASH_OF_MAPS
	MapTypeDevMap              MapType = C.BPF_MAP_TYPE_DEVMAP
	MapTypeSockMap             MapType = C.BPF_MAP_TYPE_SOCKMAP
	MapTypeCPUMap              MapType = C.BPF_MAP_TYPE_CPUMAP
	MapTypeXSKMap              MapType = C.BPF_MAP_TYPE_XSKMAP
	MapTypeSockHash            MapType = C.BPF_MAP_TYPE_SOCKHASH
	MapTypeCgroupStorage       MapType = C.BPF_MAP_TYPE_CGROUP_STORAGE
	MapTypeReusePortSockArray  MapType = C.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	MapTypePerCPUCgroupStorage MapType = C.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	MapTypeQueue               MapType = C.BPF_MAP_TYPE_QUEUE
	MapTypeStack               MapType = C.BPF_MAP_TYPE_STACK
	MapTypeSKStorage           MapType = C.BPF_MAP_TYPE_SK_STORAGE
	MapTypeDevmapHash          MapType = C.BPF_MAP_TYPE_DEVMAP_HASH
)

var mapTypeToString = map[MapType]string{
	MapTypeUnspec:              "BPF_MAP_TYPE_UNSPEC",
	MapTypeHash:                "BPF_MAP_TYPE_HASH",
	MapTypeArray:               "BPF_MAP_TYPE_ARRAY",
	MapTypeProgArray:           "BPF_MAP_TYPE_PROG_ARRAY",
	MapTypePerfEventArray:      "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
	MapTypePerCPUHash:          "BPF_MAP_TYPE_PERCPU_HASH",
	MapTypePerCPUArray:         "BPF_MAP_TYPE_PERCPU_ARRAY",
	MapTypeStackTrace:          "BPF_MAP_TYPE_STACK_TRACE",
	MapTypeCgroupArray:         "BPF_MAP_TYPE_CGROUP_ARRAY",
	MapTypeLRUHash:             "BPF_MAP_TYPE_LRU_HASH",
	MapTypeLRUPerCPUHash:       "BPF_MAP_TYPE_LRU_PERCPU_HASH",
	MapTypeLPMTrie:             "BPF_MAP_TYPE_LPM_TRIE",
	MapTypeArrayOfMaps:         "BPF_MAP_TYPE_ARRAY_OF_MAPS",
	MapTypeHashOfMaps:          "BPF_MAP_TYPE_HASH_OF_MAPS",
	MapTypeDevMap:              "BPF_MAP_TYPE_DEVMAP",
	MapTypeSockMap:             "BPF_MAP_TYPE_SOCKMAP",
	MapTypeCPUMap:              "BPF_MAP_TYPE_CPUMAP",
	MapTypeXSKMap:              "BPF_MAP_TYPE_XSKMAP",
	MapTypeSockHash:            "BPF_MAP_TYPE_SOCKHASH",
	MapTypeCgroupStorage:       "BPF_MAP_TYPE_CGROUP_STORAGE",
	MapTypeReusePortSockArray:  "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
	MapTypePerCPUCgroupStorage: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
	MapTypeQueue:               "BPF_MAP_TYPE_QUEUE",
	MapTypeStack:               "BPF_MAP_TYPE_STACK",
	MapTypeSKStorage:           "BPF_MAP_TYPE_SK_STORAGE",
	MapTypeDevmapHash:          "BPF_MAP_TYPE_DEVMAP_HASH",
}

func (t MapType) String() string {
	str, ok := mapTypeToString[t]
	if !ok {
		// MapTypeUnspec must exist in mapTypeToString to avoid infinite recursion.
		return BPFProgTypeUnspec.String()
	}

	return str
}

func (t MapType) Name() string {
	return C.GoString(C.libbpf_bpf_map_type_str(C.enum_bpf_map_type(t)))
}

//
// MapFlag
//

type MapFlag uint32

const (
	MapFlagUpdateAny     MapFlag = iota // create new element or update existing
	MapFlagUpdateNoExist                // create new element if it didn't exist
	MapFlagUpdateExist                  // update existing element
	MapFlagFLock                        // spin_lock-ed map_lookup/map_update
)

// GetMapFDByID returns a file descriptor for the map with the given ID.
func GetMapFDByID(id uint32) (int, error) {
	fdC := C.bpf_map_get_fd_by_id(C.uint(id))
	if fdC < 0 {
		return int(fdC), fmt.Errorf("could not find map id %d: %w", id, syscall.Errno(-fdC))
	}

	return int(fdC), nil
}

// CalcMapValueSize calculates the size of the value for a map.
// For per-CPU maps, it is calculated based on the number of possible CPUs.
func CalcMapValueSize(valueSize int, mapType MapType) (int, error) {
	if valueSize <= 0 {
		return 0, fmt.Errorf("value size must be greater than 0")
	}

	switch mapType {
	case MapTypePerCPUArray,
		MapTypePerCPUHash,
		MapTypeLRUPerCPUHash,
		MapTypePerCPUCgroupStorage:
		// per-CPU maps have a value size calculated using a round-up of the
		// element size multiplied by the number of possible CPUs.
		elemSize := roundUp(uint64(valueSize), 8)
		numCPU, err := NumPossibleCPUs()
		if err != nil {
			return 0, err
		}

		return int(elemSize) * numCPU, nil
	default:
		// For other maps, the value size does not change.
		return valueSize, nil
	}
}

// roundUp rounds x up to the nearest multiple of y.
func roundUp(x, y uint64) uint64 {
	return ((x + (y - 1)) / y) * y
}
