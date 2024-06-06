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
	MapFlagUpdateAny MapFlag = iota // create new element or update existing
)

// BPFMapLow provides a low-level interface to BPF maps.
// Its methods follow the BPFMap naming convention.
type BPFMapLow struct {
	fd   int
	info *BPFMapInfo
}

// GetMapByPinnedPath returns a BPFMapLow instance for the map with the given pinned path.
func GetMapByPinnedPath(pinnedPath string) (*BPFMapLow, error) {
	fd, err := OpenObjPinned(pinnedPath)
	if err != nil {
		return nil, err
	}

	info, err := GetMapInfoByFD(fd)
	if err != nil {
		return nil, err
	}

	return &BPFMapLow{
		fd:   fd,
		info: info,
	}, nil
}

func (m *BPFMapLow) FileDescriptor() int {
	return m.fd
}

func (m *BPFMapLow) ReuseFD(fd int) error {
	info, err := GetMapInfoByFD(fd)
	if err != nil {
		return fmt.Errorf("failed to reuse fd %d: %w", fd, err)
	}

	newFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to reuse fd %d: %w", fd, err)
	}

	err = syscall.Dup3(fd, newFD, syscall.O_CLOEXEC)
	if err != nil {
		_ = syscall.Close(newFD)
		return fmt.Errorf("failed to reuse fd %d: %w", fd, err)
	}

	err = syscall.Close(m.FileDescriptor())
	if err != nil {
		_ = syscall.Close(newFD)
		return fmt.Errorf("failed to reuse fd %d: %w", fd, err)
	}

	m.fd = newFD
	m.info = info

	return nil
}

func (m *BPFMapLow) Name() string {
	return m.info.Name
}

func (m *BPFMapLow) Type() MapType {
	return MapType(m.info.Type)
}

func (m *BPFMapLow) MaxEntries() uint32 {
	return m.info.MaxEntries
}

func (m *BPFMapLow) KeySize() int {
	return int(m.info.KeySize)
}

func (m *BPFMapLow) ValueSize() int {
	return int(m.info.ValueSize)
}

//
// BPFMapLow Operations
//

func (m *BPFMapLow) GetValue(key unsafe.Pointer) ([]byte, error) {
	return m.GetValueFlags(key, MapFlagUpdateAny)
}

func (m *BPFMapLow) GetValueFlags(key unsafe.Pointer, flags MapFlag) ([]byte, error) {
	valueSize, err := CalcMapValueSize(m.ValueSize(), m.Type())
	if err != nil {
		return nil, fmt.Errorf("map %s %w", m.Name(), err)
	}

	value := make([]byte, valueSize)
	retC := C.bpf_map_lookup_elem_flags(
		C.int(m.FileDescriptor()),
		key,
		unsafe.Pointer(&value[0]),
		C.ulonglong(flags),
	)
	if retC < 0 {
		return nil, fmt.Errorf("failed to lookup value %v in map %s: %w", key, m.Name(), syscall.Errno(-retC))
	}

	return value, nil
}

func (m *BPFMapLow) LookupAndDeleteElem(
	key unsafe.Pointer,
	value unsafe.Pointer,
) error {
	retC := C.bpf_map_lookup_and_delete_elem(
		C.int(m.FileDescriptor()),
		key,
		value,
	)
	if retC < 0 {
		return fmt.Errorf("failed to lookup and delete value %v in map %s: %w", key, m.Name(), syscall.Errno(-retC))
	}

	return nil
}

func (m *BPFMapLow) LookupAndDeleteElemFlags(
	key unsafe.Pointer,
	value unsafe.Pointer,
	flags MapFlag,
) error {
	retC := C.bpf_map_lookup_and_delete_elem_flags(
		C.int(m.FileDescriptor()),
		key,
		value,
		C.ulonglong(flags),
	)
	if retC < 0 {
		return fmt.Errorf("failed to lookup and delete value %v in map %s: %w", key, m.Name(), syscall.Errno(-retC))
	}

	return nil
}

func (m *BPFMapLow) GetValueAndDeleteKey(key unsafe.Pointer) ([]byte, error) {
	valueSize, err := CalcMapValueSize(m.ValueSize(), m.Type())
	if err != nil {
		return nil, fmt.Errorf("map %s %w", m.Name(), err)
	}

	value := make([]byte, valueSize)
	err = m.LookupAndDeleteElem(
		key,
		unsafe.Pointer(&value[0]),
	)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func (m *BPFMapLow) GetValueAndDeleteKeyFlags(key unsafe.Pointer, flags MapFlag) ([]byte, error) {
	valueSize, err := CalcMapValueSize(m.ValueSize(), m.Type())
	if err != nil {
		return nil, fmt.Errorf("map %s %w", m.Name(), err)
	}

	value := make([]byte, valueSize)
	err = m.LookupAndDeleteElemFlags(
		key,
		unsafe.Pointer(&value[0]),
		flags,
	)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func (m *BPFMapLow) Update(key, value unsafe.Pointer) error {
	return m.UpdateValueFlags(key, value, MapFlagUpdateAny)
}

func (m *BPFMapLow) UpdateValueFlags(key, value unsafe.Pointer, flags MapFlag) error {
	retC := C.bpf_map_update_elem(
		C.int(m.FileDescriptor()),
		key,
		value,
		C.ulonglong(flags),
	)
	if retC < 0 {
		return fmt.Errorf("failed to update map %s: %w", m.Name(), syscall.Errno(-retC))
	}

	return nil
}

func (m *BPFMapLow) DeleteKey(key unsafe.Pointer) error {
	retC := C.bpf_map_delete_elem(C.int(m.FileDescriptor()), key)
	if retC < 0 {
		return fmt.Errorf("failed to delete key %d in map %s: %w", key, m.Name(), syscall.Errno(-retC))
	}

	return nil
}

func (m *BPFMapLow) GetNextKey(key unsafe.Pointer, nextKey unsafe.Pointer) error {
	retC := C.bpf_map_get_next_key(
		C.int(m.FileDescriptor()),
		key,
		nextKey,
	)
	if retC < 0 {
		return fmt.Errorf("failed to get next key in map %s: %w", m.Name(), syscall.Errno(-retC))
	}

	return nil
}

//
// BPFMapLow Iterator
//

func (m *BPFMapLow) Iterator() *BPFMapIterator {
	return &BPFMapIterator{
		mapFD:   m.FileDescriptor(),
		keySize: m.KeySize(),
		prev:    nil,
		next:    nil,
	}
}

func Memcpy(dst, src unsafe.Pointer, size uint32) {
	C.memcpy(dst, src, C.ulong(size))
}
