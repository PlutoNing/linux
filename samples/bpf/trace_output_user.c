// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <bpf/libbpf.h>
/* 编译的命令
gcc -Wp,-MD,samples/bpf/.trace_output_user.o.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I./usr/include \
 -I./tools/testing/selftests/bpf/ -I/home/paulning/study/linux/samples/bpf/libbpf/include -I./tools/include \
 -I./tools/perf -DHAVE_ATTR_TEST=0  -c  -o samples/bpf/trace_output_user.o samples/bpf/trace_output_user.c

/home/paulning/study/llvm-project/llvm/build/bin/clang -g -O2 --target=bpf -D__TARGET_ARCH_x86   \
 -Wno-compare-distinct-pointer-types -I./include -I./samples/bpf -I./tools/include \
  -I/home/paulning/study/linux/samples/bpf/libbpf/include \
   -idirafter /home/paulning/study/llvm-project/llvm/build/lib/clang/21/include \
    -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu \
	-idirafter /usr/include       -c samples/bpf/trace_output.bpf.c -o samples/bpf/trace_output.bpf.o
gcc -Wp,-MD,samples/bpf/.trace_output.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes \
 -I./usr/include -I./tools/testing/selftests/bpf/ -I/home/paulning/study/linux/samples/bpf/libbpf/include \
  -I./tools/include -I./tools/perf -DHAVE_ATTR_TEST=0   \
   -o samples/bpf/trace_output samples/bpf/trace_output_user.o /home/paulning/study/linux/samples/bpf/libbpf/libbpf.a -lelf -lz -lrt

*/
static __u64 time_get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static __u64 start_time;
static __u64 cnt;

#define MAX_CNT 100000ll

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	struct {
		__u64 pid;
		__u64 cookie;
	} *e = data;

	if (e->cookie != 0x12345678) {
		printf("BUG pid %llx cookie %llx sized %d\n",
		       e->pid, e->cookie, size);
		return;
	}

	cnt++;

	if (cnt == MAX_CNT) {
		printf("recv %lld events per sec\n",
		       MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
		return;
	}
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct perf_buffer *pb;
	struct bpf_object *obj;
	int map_fd, ret = 0;
	char filename[256];
	FILE *f;

	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	printf("bpf filename %s\n", filename);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}
	printf("open bpf object file %s\n", filename);
	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
	if (libbpf_get_error(prog)) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	pb = perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, NULL);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}

	f = popen("taskset 1 dd if=/dev/zero of=/dev/null", "r");
	(void) f;

	start_time = time_get_ns();
	while ((ret = perf_buffer__poll(pb, 1000)) >= 0 && cnt < MAX_CNT) {
	}
	kill(0, SIGINT);

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return ret;
}
