#include "libbpfgo.h"

void p_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
	va_end(ap);
}

void p_info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static bool is_bpffs(char *path)
{
	struct statfs st_fs;

	if (statfs(path, &st_fs) < 0)
		return false;

	return (unsigned long)st_fs.f_type == BPF_FS_MAGIC;
}

int cgo_open_obj_pinned(const char *path, bool quiet)
{
	char *pname;
	int fd = -1;

	pname = strdup(path);
	if (!pname) {
		if (!quiet)
			p_err("mem alloc failed");
		goto out_ret;
	}

	fd = bpf_obj_get(pname);
	if (fd < 0) {
		if (!quiet)
			p_err("bpf obj get (%s): %s", pname,
			      errno == EACCES && !is_bpffs(dirname(pname)) ?
			    "directory not in bpf file system (bpffs)" :
			    strerror(errno));
		goto out_free;
	}

out_free:
	free(pname);
out_ret:
	return fd;
}

struct bpf_map_batch_opts *cgo_bpf_map_batch_opts_new(__u64 elem_flags, __u64 flags)
{
    struct bpf_map_batch_opts *opts;
    opts = calloc(1, sizeof(*opts));
    if (!opts)
        return NULL;

    opts->sz = sizeof(*opts);
    opts->elem_flags = elem_flags;
    opts->flags = flags;

    return opts;
}

void cgo_bpf_map_batch_opts_free(struct bpf_map_batch_opts *opts)
{
    free(opts);
}

struct bpf_map_create_opts *cgo_bpf_map_create_opts_new(__u32 btf_fd,
                                                        __u32 btf_key_type_id,
                                                        __u32 btf_value_type_id,
                                                        __u32 btf_vmlinux_value_type_id,
                                                        __u32 inner_map_fd,
                                                        __u32 map_flags,
                                                        __u64 map_extra,
                                                        __u32 numa_node,
                                                        __u32 map_ifindex)
{
    struct bpf_map_create_opts *opts;
    opts = calloc(1, sizeof(*opts));
    if (!opts)
        return NULL;

    opts->sz = sizeof(*opts);
    opts->btf_fd = btf_fd;
    opts->btf_key_type_id = btf_key_type_id;
    opts->btf_value_type_id = btf_value_type_id;
    opts->btf_vmlinux_value_type_id = btf_vmlinux_value_type_id;
    opts->inner_map_fd = inner_map_fd;
    opts->map_flags = map_flags;
    opts->map_extra = map_extra;
    opts->numa_node = numa_node;
    opts->map_ifindex = map_ifindex;

    return opts;
}

void cgo_bpf_map_create_opts_free(struct bpf_map_create_opts *opts)
{
    free(opts);
}