package main

import (
	"fmt"
	"unsafe"

	"github.com/cybwan/kylibbpfgo"
)

func main() {
	numPossibleCPUs, _ := kylibbpfgo.NumPossibleCPUs()
	fmt.Println("numPossibleCPUs:", numPossibleCPUs)

	test_fd, _ := kylibbpfgo.OpenObjPinned("/sys/fs/bpf/test")
	fmt.Println("test_fd:", test_fd)

	k := uint32(0)
	v := uint32(5)
	if err := kylibbpfgo.Update(test_fd, unsafe.Pointer(&k), unsafe.Pointer(&v)); err != nil {
		fmt.Println(err.Error())
	}
}
