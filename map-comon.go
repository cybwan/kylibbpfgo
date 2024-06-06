package kylibbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"
)

// BPFMapInfo mirrors the C structure bpf_map_info.
type BPFMapInfo struct {
	ID         uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       string
}

// GetMapInfoByFD returns the BPFMapInfo for the map with the given file descriptor.
func GetMapInfoByFD(fd int) (*BPFMapInfo, error) {
	infoC := C.cgo_bpf_map_info_new()
	defer C.cgo_bpf_map_info_free(infoC)

	infoLenC := C.cgo_bpf_map_info_size()
	retC := C.bpf_obj_get_info_by_fd(C.int(fd), unsafe.Pointer(infoC), &infoLenC)
	if retC < 0 {
		return nil, fmt.Errorf("failed to get map info for fd %d: %w", fd, syscall.Errno(-retC))
	}

	return &BPFMapInfo{
		ID:         uint32(C.cgo_bpf_map_info_id(infoC)),
		KeySize:    uint32(C.cgo_bpf_map_info_key_size(infoC)),
		ValueSize:  uint32(C.cgo_bpf_map_info_value_size(infoC)),
		MaxEntries: uint32(C.cgo_bpf_map_info_max_entries(infoC)),
		MapFlags:   uint32(C.cgo_bpf_map_info_map_flags(infoC)),
		Name:       C.GoString(C.cgo_bpf_map_info_name(infoC)),
	}, nil
}
