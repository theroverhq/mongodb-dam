#ifndef __MONGODB_DAM_VMLINUX_MIN_H__
#define __MONGODB_DAM_VMLINUX_MIN_H__

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};
#endif

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    __u16 skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
    int sk_err;
} __attribute__((preserve_access_index));
struct sk_buff;
struct bpf_perf_event_data;

struct tcp_sock {
    __u32 srtt_us;
    __u32 snd_wnd;
} __attribute__((preserve_access_index));

enum bpf_map_type {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
    BPF_ANY = 0,
};

#define BPF_F_USER_STACK (1ULL << 8)

#endif
