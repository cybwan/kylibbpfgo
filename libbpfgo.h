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
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h> // uapi

int cgo_open_obj_pinned(const char *path, bool quiet);

#endif
