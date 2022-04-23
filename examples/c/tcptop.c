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


static struct ipvx_key_t ipv4_send[MAX_ENTRIES],ipv4_recv[MAX_ENTRIES],
           ipv6_send[MAX_ENTRIES],ipv6_recv[MAX_ENTRIES];
static __u64 ipv4_send_count[MAX_ENTRIES],ipv4_recv_count[MAX_ENTRIES],
       ipv6_send_count[MAX_ENTRIES],ipv6_recv_count[MAX_ENTRIES];


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

static int counts_map_v4(int fd,int send)
{
    __u32 key_size = sizeof(ipv4_send[0]);
    __u32 value_size = sizeof(__u64);
    static struct ipvx_key_t zero;
    __u32 n = MAX_ENTRIES;

    if(send) {
        if(dump_hash(fd, ipv4_send, key_size, ipv4_send_count, value_size, &n, &zero)) {
            warn("dump_hash: %s", strerror(errno));
        }
    } else {
        if(dump_hash(fd, ipv4_send, key_size, ipv4_recv_count, value_size, &n, &zero)) {
            warn("dump_hash: %s", strerror(errno));
        }
    }

    return 0;
}


static int counts_map_v6(int fd,int send)
{
    __u32 key_size = sizeof(ipv6_send[0]);
    __u32 value_size = sizeof(__u64);
    static struct ipvx_key_t zero;
    __u32 n = MAX_ENTRIES;

    if(send) {
        if(dump_hash(fd, ipv6_send, key_size, ipv6_send_count, value_size, &n, &zero)) {
            fprintf(stderr, "dump_hash");
        }
    } else {
        if(dump_hash(fd, ipv4_recv, key_size, ipv6_recv_count, value_size, &n, &zero)) {
            fprintf(stderr, "dump_hash");
        }
    }

    return 0;
}


static void clean_ipv4(int map_fd)
{
    __u64 val = 0;
    for(int i=0; i< MAX_ENTRIES; i++) {
        bpf_map_update_elem(map_fd, &ipv4_send[i], &val, BPF_EXIST);
        bpf_map_update_elem(map_fd, &ipv4_recv[i], &val, BPF_EXIST);
    }
}

static struct ipvx_node* merge_node(struct ipvx_node* head, struct ipvx_node* tail)
{
	struct ipvx_node* tmp = malloc(sizeof(struct ipvx_node));
	memset(tmp, 0, sizeof(struct ipvx_node));
	struct ipvx_node *res = tmp, *left =head, *right = tail;
	while(left != NULL && right != NULL){
		if(left->tx+left->rx > right->tx + right->rx){
			res->next = left;
			left = left->next;
		} else{
			res->next = right;
			right = right->next;
		}
		res = res->next;
	}
	if(left != NULL){
		res->next = left;
	} else if(right != NULL){
		res->next = right;
	}
	return tmp->next;
}
// link:https://leetcode-cn.com/problems/sort-list/solution/pai-xu-lian-biao-by-leetcode-solution/
static struct ipvx_node* sort_node(struct ipvx_node *head, struct ipvx_node *tail) {
	if(head == NULL){
		return head;
	}
	if(head->next == tail){
		head->next = NULL;
		return head;
	}
	struct ipvx_node *fast = head, *slow=head;
	while(fast != tail){
		fast = fast->next;
		slow = slow->next;
		if(fast != tail){
			fast = fast->next;
		}
	}
	struct ipvx_node *mid = slow;
	return merge_node(sort_node(head, mid), sort_node(mid,tail));
}

static void print_node(struct ipvx_node *head,int ipv4) {
    head = sort_node(head, NULL);
    while(head) {
        if(head->pid && ipv4) {
            char laddr[INET_ADDRSTRLEN];
            char daddr[INET_ADDRSTRLEN];
            struct in_addr l4 = {
                .s_addr = head->laddr
            };
            struct in_addr d4 = {
                .s_addr = head->daddr
            };

            printf("%-7d\t\t%-12s\t\t%s:%-21d\t\t%s:%-21d\t%-6lld\t%-6lld\n",
                   head->pid, head->name,
                   inet_ntop(AF_INET, &l4, laddr, sizeof(laddr)),
                   head->lport,
                   inet_ntop(AF_INET, &d4, daddr, sizeof(daddr)),
                   head->dport,
                   head->rx, head->tx);
        }

        head = head->next;
    }
}

int main(int argc, char **argv)
{

    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct tcptop_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if(env.interval == 0) {
        printf("等待时间不允许为空\n");
        return err;
    }
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = tcptop_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Parameterize BPF code with minimum duration parameter */
    if(env.ipv4) {
        skel->rodata->filter_family = env.ipv4;
    }

    if(env.ipv6) {
        skel->rodata->filter_family = env.ipv6;
    }

    if(env.pid) {
        skel->rodata->filter_pid = env.pid;
    }
    /* Load & verify BPF programs */
    err = tcptop_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = tcptop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Process events */
    while (!exiting) {
        sleep(env.interval);
        printf("\e[1;1H\e[2J");

        printf("%-7s\t\t%-12s\t\t%-21s\t\t\t\t%-21s\t\t\t%-6s\t%-6s\n",
               "PID", "COMM", "LADDR", "RADDR", "RX_KB", "TX_KB");
        int recv4_fd = bpf_map__fd(skel->maps.ipv4_recv_bytes);
        counts_map_v4(recv4_fd, 0);
        int send4_fd = bpf_map__fd(skel->maps.ipv4_send_bytes);
        counts_map_v4(send4_fd, 1);

        struct ipvx_node *next = (struct ipvx_node*)malloc(sizeof(struct ipvx_node));
        memset(next, 0, sizeof(struct ipvx_node));
        struct ipvx_node *tmp = next;
        for(int i=0; i < MAX_ENTRIES; i++)
        {
            if(ipv4_recv_count[i] != 0 ||  ipv4_send_count[i] != 0)
            {
                next->daddr = ipv4_send[i].daddr;
                next->dport = ipv4_send[i].dport;
                next->laddr = ipv4_send[i].laddr;
                next->lport = ipv4_send[i].lport;
                memcpy(next->name, ipv4_send[i].name, sizeof(ipv4_send[i].name));
                next->pid = ipv4_send[i].pid;
                next->rx = ipv4_recv_count[i];
                next->tx = ipv4_send_count[i];
                next->next = (struct ipvx_node*)malloc(sizeof(struct ipvx_node));
                memset(next->next, 0, sizeof(struct ipvx_node));
                next = next->next;
            }
        }
        print_node(tmp,1);
        clean_ipv4(recv4_fd);
        clean_ipv4(send4_fd);


        printf("\n\n%-7s %-12s %-32s %-32s %-6s %-6s\n",
               "PID", "COMM", "LADDR", "RADDR", "RX_KB", "TX_KB");

        int recv6_fd = bpf_map__fd(skel->maps.ipv6_recv_bytes);
        counts_map_v6(recv6_fd, 0);
        int send6_fd = bpf_map__fd(skel->maps.ipv6_send_bytes);
        counts_map_v6(send6_fd, 1);
        for(int i=0; i < MAX_ENTRIES; i++)
        {
            if(ipv6_recv_count[i] != 0 ||  ipv6_send_count[i] != 0)
            {
                char laddr[INET6_ADDRSTRLEN];
                char daddr[INET6_ADDRSTRLEN];
                struct in6_addr l6 = {};
                struct in6_addr d6 = {};
                printf("%-7d %-12s %-32s %-32s %-6lld %-6lld\n",
                       ipv6_recv[i].pid, ipv6_recv[i].name,
                       inet_ntop(AF_INET6, &l6, laddr, sizeof(laddr)),
                       inet_ntop(AF_INET6, &d6, daddr, sizeof(daddr)),
                       ipv6_recv_count[i], ipv6_send_count[i]);
            }
        }
    }

cleanup:
    /* Clean up */
    tcptop_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
