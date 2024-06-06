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

//
// BPFMapLow (low-level API)
//

// BPFMapLow provides a low-level interface to BPF maps.
// Its methods follow the BPFMap naming convention.
type BPFMapLow struct {
	fd int
}

func (m *BPFMapLow) Update(key, value unsafe.Pointer) error {
	return m.UpdateValueFlags(key, value, MapFlagUpdateAny)
}

func (m *BPFMapLow) UpdateValueFlags(key, value unsafe.Pointer, flags MapFlag) error {
	retC := C.bpf_map_update_elem(
		C.int(m.fd),
		key,
		value,
		C.ulonglong(flags),
	)
	if retC < 0 {
		return fmt.Errorf("failed to update map %d: %w", m.fd, syscall.Errno(-retC))
	}

	return nil
}

func (m *BPFMapLow) DeleteKey(key unsafe.Pointer) error {
	retC := C.bpf_map_delete_elem(C.int(m.fd), key)
	if retC < 0 {
		return fmt.Errorf("failed to delete key %d in map %d: %w", key, m.fd, syscall.Errno(-retC))
	}

	return nil
}
