#ifndef __LIBBPF_GO_H__
#define __LIBBPF_GO_H__

#define BPF_FS_MAGIC 0xcafe4a11

#ifdef __powerpc64__
    #define __SANE_USERSPACE_TYPES__ 1
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <sys/resource.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h> // uapi

int cgo_open_obj_pinned(const char *path, bool quiet);

struct bpf_map_create_opts *cgo_bpf_map_create_opts_new(__u32 btf_fd,
                                                        __u32 btf_key_type_id,
                                                        __u32 btf_value_type_id,
                                                        __u32 btf_vmlinux_value_type_id,
                                                        __u32 inner_map_fd,
                                                        __u32 map_flags,
                                                        __u64 map_extra,
                                                        __u32 numa_node,
                                                        __u32 map_ifindex);
void cgo_bpf_map_create_opts_free(struct bpf_map_create_opts *opts);

struct bpf_map_batch_opts *cgo_bpf_map_batch_opts_new(__u64 elem_flags, __u64 flags);
void cgo_bpf_map_batch_opts_free(struct bpf_map_batch_opts *opts);

#endif
