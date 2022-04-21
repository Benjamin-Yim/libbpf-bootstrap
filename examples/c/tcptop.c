// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bits/socket.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcptop.h"
#include "tcptop.skel.h"
#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct env {
	bool noclear;
	bool nosummary;
	pid_t pid;
	int interval;
	long count;
	bool cgroupmap;
	bool mntnsmap;
	int ipv4;
	int ipv6;
	bool ebpf;
} env;

struct tcp_session {
	__u32 pid;
    char name[TASK_COMM_LEN];
    __u32 laddr;
    __u16 lport;
    __u32 daddr;
    __u16 dport;
};

const char *argp_program_version = "tcptop";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"examples:\n"
"tcptop         trace TCP send/recv by host\n"
"tcptop -C      don't clean the screen\n"
"tcptop -p 181  only trace PID 181\n"
"tcptop --cgroupmap mappath	only trace cgroups in this BPF map\n"
"tcptop --mntnsmap mappath	only trace mount namespaces in the map"
"tcptop -4	trace IPv4 family only"
"tcptop -6	trace IPv6 family only"
"USAGE: ./tcptop [-C <noclear>] [-S <nosummary>] [-p <pid>] "
"[interval] [count] [<cgroupmap>] [<mntnsmap>] [-4 <ipv4>] [-6 <ipv6>] [<ebpf>]\n";

static const struct argp_option opts[] = {
	{ "noclear", 'C', "NOCLEAR", 0, "don't clear the screen" },
	{ "nosummary", 'S', "NOSUMMRY", 0, "skip system summary line" },
	{ "pid", 'p', "PID", 0, "trace this PID only" },
	{ "interval", 'i', "INTERVAL", 1, "output interval, in seconds (default 1)" },
	{ "count", 'c', "COUNT", -1, "number of outputs" },
	{ "cgroupmap", 'g', "CGROUPMAP", 0, "trace cgroups in this BPF map only" },
	{ "mntnsmap", 'n', "MNTNSMAP", 0, "trace mount namespaces in this BPF map only" },
	{ "ipv4", '4', "IPV4", 0, "trace IPv4 family only" },
	{ "ipv6", '6', "IPV6", 0, "trace IPv6 family only" },
	{ "ebpf", 'e', "EBPF", 0, NULL },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'C':
		env.noclear = strtol(arg, NULL, 10);
		break;
	case 'S':
		env.nosummary = strtol(arg, NULL, 10);
		break;
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		break;
	case 'c':
		env.count = strtol(arg, NULL, 10);
		break;
	case 'g':
		env.cgroupmap = strtol(arg, NULL, 10);
		break;
	case 'n':
		env.mntnsmap = strtol(arg, NULL, 10);
		break;
	case '4':
		env.ipv4 = AF_INET;
		break;
	case '6':
		env.ipv6 = AF_INET6;
		break;
	case 'e':
		env.ebpf = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}
static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}

static int counts_map_v4(int fd,
					   struct ipv4_key_t keys[MAX_ENTRIES],
					   __u64 counts[MAX_ENTRIES])
{
	__u32 key_size = sizeof(keys[0]);
	__u32 value_size = sizeof(__u64);
	static struct ipv4_key_t zero;
	__u32 n = MAX_ENTRIES;

	if(dump_hash(fd, keys, key_size, counts, value_size, &n, &zero)){
		warn("dump_hash: %s", strerror(errno));
	}

	return 0;
}


static int counts_map_v6(int fd,
					   struct ipv6_key_t keys[MAX_ENTRIES],
					   __u64 counts[MAX_ENTRIES])
{
	__u32 key_size = sizeof(keys[0]);
	__u32 value_size = sizeof(__u64);
	static struct ipv6_key_t zero;
	__u32 n = MAX_ENTRIES;

	if(dump_hash(fd, keys, key_size, counts, value_size, &n, &zero)){
		fprintf(stderr, "dump_hash");
	}

	return 0;
}

int main(int argc, char **argv)
{

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct in_addr l4 = {};
	struct in_addr d4 = {};
	struct in6_addr l6 = {};
	struct in6_addr d6 = {};
	struct tcptop *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = tcptop__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	if(env.ipv4){
		skel->rodata->filter_family = env.ipv4;
	}

	if(env.ipv6){
		skel->rodata->filter_family = env.ipv6;
	}

	if(env.pid){
		skel->rodata->filter_pid = env.pid;
	}
	/* Load & verify BPF programs */
	err = tcptop__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = tcptop__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/*  */

	static struct ipv4_key_t ipv4_send[MAX_ENTRIES],ipv4_recv[MAX_ENTRIES];
	static struct ipv6_key_t ipv6_send[MAX_ENTRIES],ipv6_recv[MAX_ENTRIES];
	static __u64 ipv4_send_count[MAX_ENTRIES],ipv4_recv_count[MAX_ENTRIES],
	ipv6_send_count[MAX_ENTRIES],ipv6_recv_count[MAX_ENTRIES];
	/* Process events */
	while (!exiting) {
		sleep(env.interval);
		printf("\n");

		printf("%-7s %-12s %-21s %-21s %-6s %-6s\n",
	       "PID", "COMM", "LADDR", "DADDR", "RX_KB", "TX_KB");
		int fd = bpf_map__fd(skel->maps.ipv4_recv_bytes);
		counts_map_v4(fd, ipv4_recv, ipv4_recv_count);
		fd = bpf_map__fd(skel->maps.ipv4_send_bytes);
		counts_map_v4(fd, ipv4_send,ipv4_send_count);

		int i;
		for(i=0;i < MAX_ENTRIES;i++)
		{
			char laddr[INET_ADDRSTRLEN];
			char daddr[INET_ADDRSTRLEN];

			printf("%-7d %-12s %-21s %-21s %-6lld %-6lld\n",
			ipv4_recv[i].pid, ipv4_recv[i].name,
			inet_ntop(AF_INET, &l4, laddr, sizeof(laddr)), inet_ntop(AF_INET, &d4, daddr, sizeof(daddr)),
			ipv4_recv_count[i], ipv4_send_count[i]);
		}


		printf("%-7s %-12s %-32s %-32s %-6s %-6s\n",
	       "PID", "COMM", "LADDR", "DADDR", "RX_KB", "TX_KB");
		fd = bpf_map__fd(skel->maps.ipv6_recv_bytes);
		counts_map_v6(fd, ipv6_recv,ipv6_recv_count);
		fd = bpf_map__fd(skel->maps.ipv6_send_bytes);
		counts_map_v6(fd, ipv6_send, ipv6_send_count);
		for(i=0;i < MAX_ENTRIES;i++)
		{
			char laddr[INET6_ADDRSTRLEN];
			char daddr[INET6_ADDRSTRLEN];
			printf("%-7d %-12s %-32s %-32s %-6lld %-6lld\n",
			ipv6_recv[i].pid, ipv6_recv[i].name,
			inet_ntop(AF_INET6, &l6, laddr, sizeof(laddr)),
			inet_ntop(AF_INET6, &d6, daddr, sizeof(daddr)),
			ipv6_recv_count[i], ipv6_send_count[i]);
		}

	}

cleanup:
	/* Clean up */
	tcptop__destroy(skel);

	return err < 0 ? -err : 0;
}
