package main

import (
	"fmt"
	"unsafe"

	"github.com/cybwan/kylibbpfgo"
)

func main() {
	numPossibleCPUs, _ := kylibbpfgo.NumPossibleCPUs()
	fmt.Println("numPossibleCPUs:", numPossibleCPUs)

	test_fd, _ := kylibbpfgo.OpenObjPinned("/sys/fs/bpf/f4gw_progs")
	fmt.Println("test_fd:", test_fd)

	egress_fd, _ := kylibbpfgo.OpenObjPinned("/sys/fs/bpf/gateway/xdp_egress")
	fmt.Println("ingress_fd:", egress_fd)

	k := uint32(2)
	if err := kylibbpfgo.Update(test_fd, unsafe.Pointer(&k), unsafe.Pointer(&egress_fd)); err != nil {
		fmt.Println(err.Error())
	}
}
