package main

import (
	"fmt"

	"github.com/cybwan/kylibbpfgo"
)

func main() {
	numPossibleCPUs, _ := kylibbpfgo.NumPossibleCPUs()
	fmt.Println("numPossibleCPUs:", numPossibleCPUs)

	f4gw_progs_fd, _ := kylibbpfgo.OpenObjPinned("/sys/fs/bpf/f4gw_progs")
	fmt.Println("f4gw_progs_fd:", f4gw_progs_fd)
}
