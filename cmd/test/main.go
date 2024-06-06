package main

import (
	"fmt"
	"unsafe"

	"github.com/cybwan/kylibbpfgo"
)

func main() {
	numPossibleCPUs, _ := kylibbpfgo.NumPossibleCPUs()
	fmt.Println("numPossibleCPUs:", numPossibleCPUs)

	f4gw_progs_fd, _ := kylibbpfgo.OpenObjPinned("/sys/fs/bpf/f4gw_progs")
	fmt.Println("f4gw_progs_fd:", f4gw_progs_fd)

	k := uint32(0)
	v := uint32(5)
	if err := kylibbpfgo.Update(f4gw_progs_fd, unsafe.Pointer(&k), unsafe.Pointer(&v)); err != nil {
		fmt.Println(err.Error())
	}
}
