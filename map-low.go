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

type MapFlag uint32

const (
	MapFlagUpdateAny     MapFlag = iota // create new element or update existing
	MapFlagUpdateNoExist                // create new element if it didn't exist
	MapFlagUpdateExist                  // update existing element
	MapFlagFLock                        // spin_lock-ed map_lookup/map_update
)

func GetValue(fd int, key unsafe.Pointer, valueSize uint32) ([]byte, error) {
	return GetValueFlags(fd, key, valueSize, MapFlagUpdateAny)
}

func GetValueFlags(fd int, key unsafe.Pointer, valueSize uint32, flags MapFlag) ([]byte, error) {
	value := make([]byte, valueSize)
	retC := C.bpf_map_lookup_elem_flags(
		C.int(fd),
		key,
		unsafe.Pointer(&value[0]),
		C.ulonglong(flags),
	)
	if retC < 0 {
		return nil, fmt.Errorf("failed to lookup value %v in map %d: %w", key, fd, syscall.Errno(-retC))
	}

	return value, nil
}

func Update(fd int, key, value unsafe.Pointer) error {
	return UpdateValueFlags(fd, key, value, MapFlagUpdateAny)
}

func UpdateValueFlags(fd int, key, value unsafe.Pointer, flags MapFlag) error {
	retC := C.bpf_map_update_elem(
		C.int(fd),
		key,
		value,
		C.ulonglong(flags),
	)
	if retC < 0 {
		return fmt.Errorf("failed to update map %d: %w", fd, syscall.Errno(-retC))
	}

	return nil
}

func DeleteKey(fd int, key unsafe.Pointer) error {
	retC := C.bpf_map_delete_elem(C.int(fd), key)
	if retC < 0 {
		return fmt.Errorf("failed to delete key %d in map %d: %w", key, fd, syscall.Errno(-retC))
	}
	return nil
}

func Memcpy(dst, src unsafe.Pointer, size uint32) {
	C.memcpy(dst, src, C.long(size))
}
