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
// BPFMapLow Batch Operations
//

// GetValueBatch gets the values with the given keys from the map.
// It returns the values and the number of read elements.
func (m *BPFMapLow) GetValueBatch(keys, startKey, nextKey unsafe.Pointer, count uint32) ([][]byte, uint32, error) {
	valueSize, err := CalcMapValueSize(m.ValueSize(), m.Type())
	if err != nil {
		return nil, 0, fmt.Errorf("map %s %w", m.Name(), err)
	}

	var (
		values    = make([]byte, valueSize*int(count))
		valuesPtr = unsafe.Pointer(&values[0])
		countC    = C.uint(count)
	)

	optsC, errno := C.cgo_bpf_map_batch_opts_new(C.BPF_ANY, C.BPF_ANY)
	if optsC == nil {
		return nil, 0, fmt.Errorf("failed to create bpf_map_batch_opts: %w", errno)
	}
	defer C.cgo_bpf_map_batch_opts_free(optsC)

	// The batch APIs are a bit different in which they can return an error, but
	// depending on the errno code, it might mean a complete error (nothing was
	// done) or a partial success (some elements were processed).
	//
	// - On complete sucess, it will return 0, and errno won't be set.
	// - On partial sucess, it will return -1, and errno will be set to ENOENT.
	// - On error, it will return -1, and an errno different to ENOENT.
	retC := C.bpf_map_lookup_batch(
		C.int(m.FileDescriptor()),
		startKey,
		nextKey,
		keys,
		valuesPtr,
		&countC,
		optsC,
	)
	errno = syscall.Errno(-retC)
	// retC < 0 && errno == syscall.ENOENT indicates a partial read.
	if retC < 0 && (errno != syscall.ENOENT || countC == 0) {
		return nil, 0, fmt.Errorf("failed to batch get value %v in map %s: %w", keys, m.Name(), errno)
	}

	// Either some or all elements were read.
	return collectBatchValues(values, uint32(countC), valueSize), uint32(countC), nil
}

// GetValueAndDeleteBatch gets the values with the given keys from the map and
// deletes them.
// It returns the values and the number of deleted elements.
func (m *BPFMapLow) GetValueAndDeleteBatch(keys, startKey, nextKey unsafe.Pointer, count uint32) ([][]byte, uint32, error) {
	valueSize, err := CalcMapValueSize(m.ValueSize(), m.Type())
	if err != nil {
		return nil, 0, fmt.Errorf("map %s %w", m.Name(), err)
	}

	var (
		values    = make([]byte, valueSize*int(count))
		valuesPtr = unsafe.Pointer(&values[0])
		countC    = C.uint(count)
	)

	optsC, errno := C.cgo_bpf_map_batch_opts_new(C.BPF_ANY, C.BPF_ANY)
	if optsC == nil {
		return nil, 0, fmt.Errorf("failed to create bpf_map_batch_opts: %w", errno)
	}
	defer C.cgo_bpf_map_batch_opts_free(optsC)

	retC := C.bpf_map_lookup_and_delete_batch(
		C.int(m.FileDescriptor()),
		startKey,
		nextKey,
		keys,
		valuesPtr,
		&countC,
		optsC,
	)
	errno = syscall.Errno(-retC)
	// retC < 0 && errno == syscall.ENOENT indicates a partial read and delete.
	if retC < 0 && (errno != syscall.ENOENT || countC == 0) {
		return nil, 0, fmt.Errorf("failed to batch lookup and delete values %v in map %s: %w", keys, m.Name(), errno)
	}

	// Either some or all elements were read and deleted.
	return collectBatchValues(values, uint32(countC), valueSize), uint32(countC), nil
}

// UpdateBatch updates the elements with the given keys and values in the map.
// It returns the number of updated elements.
func (m *BPFMapLow) UpdateBatch(keys, values unsafe.Pointer, count uint32) (uint32, error) {
	countC := C.uint(count)

	optsC, errno := C.cgo_bpf_map_batch_opts_new(C.BPF_ANY, C.BPF_ANY)
	if optsC == nil {
		return 0, fmt.Errorf("failed to create bpf_map_batch_opts: %w", errno)
	}
	defer C.cgo_bpf_map_batch_opts_free(optsC)

	retC := C.bpf_map_update_batch(
		C.int(m.FileDescriptor()),
		keys,
		values,
		&countC,
		optsC,
	)
	errno = syscall.Errno(-retC)
	// retC < 0 && errno == syscall.E2BIG indicates a partial update.
	if retC < 0 && (errno != syscall.E2BIG || countC == 0) {
		return 0, fmt.Errorf("failed to batch update values %v in map %s: %w", keys, m.Name(), errno)
	}

	// Either some or all elements were updated.
	return uint32(countC), nil
}

// DeleteKeyBatch deletes the elements with the given keys from the map.
// It returns the number of deleted elements.
func (m *BPFMapLow) DeleteKeyBatch(keys unsafe.Pointer, count uint32) (uint32, error) {
	countC := C.uint(count)

	optsC, errno := C.cgo_bpf_map_batch_opts_new(C.BPF_ANY, C.BPF_ANY)
	if optsC == nil {
		return 0, fmt.Errorf("failed to create bpf_map_batch_opts: %w", errno)
	}
	defer C.cgo_bpf_map_batch_opts_free(optsC)

	retC := C.bpf_map_delete_batch(
		C.int(m.FileDescriptor()),
		keys,
		&countC,
		optsC,
	)
	errno = syscall.Errno(-retC)
	// retC < 0 && errno == syscall.ENOENT indicates a partial deletion.
	if retC < 0 && (errno != syscall.ENOENT || countC == 0) {
		return 0, fmt.Errorf("failed to batch delete keys %v in map %s: %w", keys, m.Name(), errno)
	}

	// Either some or all elements were deleted.
	return uint32(countC), nil
}

func collectBatchValues(values []byte, count uint32, valueSize int) [][]byte {
	var value []byte
	var collected [][]byte

	for i := 0; i < int(count*uint32(valueSize)); i += valueSize {
		value = values[i : i+valueSize]
		collected = append(collected, value)
	}

	return collected
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
