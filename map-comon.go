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
	ID                    uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	Name                  string
	IfIndex               uint32
	BTFVmlinuxValueTypeID uint32
	NetnsDev              uint64
	NetnsIno              uint64
	BTFID                 uint32
	BTFKeyTypeID          uint32
	BTFValueTypeID        uint32
	MapExtra              uint64
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
		ID:                    uint32(C.cgo_bpf_map_info_id(infoC)),
		KeySize:               uint32(C.cgo_bpf_map_info_key_size(infoC)),
		ValueSize:             uint32(C.cgo_bpf_map_info_value_size(infoC)),
		MaxEntries:            uint32(C.cgo_bpf_map_info_max_entries(infoC)),
		MapFlags:              uint32(C.cgo_bpf_map_info_map_flags(infoC)),
		Name:                  C.GoString(C.cgo_bpf_map_info_name(infoC)),
		IfIndex:               uint32(C.cgo_bpf_map_info_ifindex(infoC)),
		BTFVmlinuxValueTypeID: uint32(C.cgo_bpf_map_info_btf_vmlinux_value_type_id(infoC)),
		NetnsDev:              uint64(C.cgo_bpf_map_info_netns_dev(infoC)),
		NetnsIno:              uint64(C.cgo_bpf_map_info_netns_ino(infoC)),
		BTFID:                 uint32(C.cgo_bpf_map_info_btf_id(infoC)),
		BTFKeyTypeID:          uint32(C.cgo_bpf_map_info_btf_key_type_id(infoC)),
		BTFValueTypeID:        uint32(C.cgo_bpf_map_info_btf_value_type_id(infoC)),
		MapExtra:              uint64(C.cgo_bpf_map_info_map_extra(infoC)),
	}, nil
}
