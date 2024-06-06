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

#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h> // uapi

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

/* keep in sync with the definition in skeleton/pid_iter.bpf.c */
enum bpf_obj_type {
	BPF_OBJ_UNKNOWN,
	BPF_OBJ_PROG,
	BPF_OBJ_MAP,
	BPF_OBJ_LINK,
	BPF_OBJ_BTF,
};

int cgo_open_obj_pinned(const char *path, bool quiet);

int cgo_open_obj_pinned_any(const char *path, enum bpf_obj_type exp_type);
#endif
