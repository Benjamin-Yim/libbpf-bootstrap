/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __TCPTOP_H
#define __TCPTOP_H

#include <asm-generic/errno.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

struct ipv4_key_t {
    __u32 pid;
    char name[TASK_COMM_LEN];
    __u32 laddr;
    __u32 daddr;
    __u16 lport;
    __u16 dport;
};


struct ipv6_key_t {
    __u32 pid;
    char name[TASK_COMM_LEN];
    __u32 laddr;
    __u32 daddr;
    __u16 lport;
    __u16 dport;
};

#endif
