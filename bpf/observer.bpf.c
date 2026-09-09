#include "vmlinux_min.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_CAPTURE_BYTES 1024
#define MAX_VECTOR_CHUNKS 2
#define TCP_ESTABLISHED_STATE 1
#define TCP_SYN_SENT_STATE 2
#define TCP_SYN_RECV_STATE 3
#define TCP_CLOSE_STATE 7
#define ECONNRESET_CODE 104
#define ETIMEDOUT_CODE 110

#if defined(__TARGET_ARCH_x86)
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_PREAD64 17
#define SYS_PWRITE64 18
#define SYS_READV 19
#define SYS_WRITEV 20
#define SYS_SENDTO 44
#define SYS_RECVFROM 45
#define SYS_SENDMSG 46
#define SYS_RECVMSG 47
#define SYS_FSYNC 74
#define SYS_FDATASYNC 75
#define SYS_OPENAT 257
#elif defined(__TARGET_ARCH_arm64)
#define SYS_OPENAT 56
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_READV 65
#define SYS_WRITEV 66
#define SYS_PREAD64 67
#define SYS_PWRITE64 68
#define SYS_FSYNC 82
#define SYS_FDATASYNC 83
#define SYS_SENDTO 206
#define SYS_RECVFROM 207
#define SYS_SENDMSG 211
#define SYS_RECVMSG 212
#else
#error unsupported architecture
#endif

enum event_type {
    EVENT_IO_CHUNK = 1,
    EVENT_SYSCALL_LATENCY = 2,
    EVENT_CONNECTION = 3,
    EVENT_PROFILE = 4,
    EVENT_PROCESS = 5,
    EVENT_DNS_CHUNK = 6,
};

enum direction {
    DIRECTION_NONE = 0,
    DIRECTION_INBOUND = 1,
    DIRECTION_OUTBOUND = 2,
};

enum capture_source {
    SOURCE_SYSCALL = 1,
    SOURCE_OPENSSL = 2,
    SOURCE_KERNEL = 3,
    SOURCE_PERF = 4,
    SOURCE_USER_UPROBE = 5,
};

enum operation {
    OP_NONE = 0,
    OP_PREAD = 1,
    OP_PWRITE = 2,
    OP_FSYNC = 3,
    OP_OPENAT = 4,
    OP_OFFCPU = 5,
    OP_TCP_CONNECT = 6,
    OP_TCP_ACCEPT = 7,
    OP_TCP_CLOSE = 8,
    OP_TCP_RTT = 9,
    OP_TCP_RETRANSMIT = 10,
    OP_CPU_SAMPLE = 11,
    OP_FDATASYNC = 12,
    OP_LOCK_WAIT = 13,
    OP_PAGE_FAULT = 14,
    OP_PROCESS_EXEC = 15,
    OP_PROCESS_EXIT = 16,
    OP_TCP_HANDSHAKE = 17,
    OP_TCP_RESET_RECEIVED = 18,
    OP_TCP_RESET_SENT = 19,
    OP_TCP_ZERO_WINDOW = 20,
    OP_TCP_TIMEOUT = 21,
};

struct trace_event_raw_sys_enter {
    __u64 common;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    __u64 common;
    long id;
    long ret;
};

struct trace_event_raw_sched_switch {
    __u64 common;
    char prev_comm[TASK_COMM_LEN];
    __s32 prev_pid;
    __s32 prev_prio;
    long prev_state;
    char next_comm[TASK_COMM_LEN];
    __s32 next_pid;
    __s32 next_prio;
};

struct trace_event_raw_sched_process_template {
    __u64 common;
    char comm[TASK_COMM_LEN];
    __s32 pid;
    __s32 old_pid;
};

struct user_iovec {
    void *iov_base;
    __u64 iov_len;
};

struct user_msghdr {
    void *msg_name;
    __u32 msg_namelen;
    __u32 padding;
    struct user_iovec *msg_iov;
    __u64 msg_iovlen;
};

struct pending_read {
    __u64 buffer;
    __u64 length_pointer;
    __u64 requested;
    __u64 connection_key;
    __s32 fd;
    __u8 source;
    __u8 vector_kind;
    __u8 is_ex;
    __u8 direction;
    __u8 is_network;
    __u8 protocol;
    __u8 padding[2];
};

struct syscall_start {
    __u64 started_ns;
    __u64 requested;
    __s32 fd;
    __u8 operation;
    __u8 padding[3];
};

struct socket_owner {
    __u64 connection_key;
    __u32 tgid;
    __s32 fd;
};

struct kernel_event {
    __u64 timestamp_ns;
    __u64 connection_key;
    __u64 cgroup_id;
    __u64 duration_ns;
    __u64 bytes;
    __s64 result;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __s32 fd;
    __u32 original_len;
    __u32 captured_len;
    __u8 event_type;
    __u8 direction;
    __u8 source;
    __u8 operation;
    char comm[TASK_COMM_LEN];
    __u8 data[MAX_CAPTURE_BYTES];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} target_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u32);
} target_threads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_read);
} pending_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct syscall_start);
} syscall_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u64);
} lock_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u64);
} fault_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u64);
} offcpu_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct socket_owner);
} tracked_sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} rtt_last_emit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} handshake_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} completed_handshakes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} peer_resets_seen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u8);
} tls_depth SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __s32);
} ssl_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 16384);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

const volatile __u32 capture_bytes = 1024;
const volatile __u16 mongodb_port = 27017;
const volatile __u64 rtt_sample_interval_ns = 1000000000ULL;
const volatile __u64 lock_wait_threshold_ns = 50000ULL;
const volatile __u64 page_fault_threshold_ns = 100000ULL;
const volatile __u64 offcpu_threshold_ns = 1000000ULL;

static __always_inline int is_target_tgid(__u32 tgid)
{
    return bpf_map_lookup_elem(&target_tgids, &tgid) != 0;
}

static __always_inline void count_drop(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&dropped_events, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline struct kernel_event *reserve_event(void)
{
    struct kernel_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->connection_key = 0;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->duration_ns = 0;
    event->bytes = 0;
    event->result = 0;
    event->pid = (__u32)pid_tgid;
    event->tgid = pid_tgid >> 32;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->fd = -1;
    event->original_len = 0;
    event->captured_len = 0;
    event->event_type = 0;
    event->direction = 0;
    event->source = 0;
    event->operation = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    return event;
}

static __always_inline void submit_chunk_limited(
    __u64 buffer,
    __u64 requested,
    __s64 actual,
    __s32 fd,
    __u8 direction,
    __u8 source,
    __u64 connection_key,
    __u8 event_type,
    __u32 copy_limit)
{
    if (actual <= 0 || buffer == 0 || copy_limit == 0)
        return;
    struct kernel_event *event = reserve_event();
    if (!event)
        return;
    __u32 limit = copy_limit;
    if (limit > MAX_CAPTURE_BYTES)
        limit = MAX_CAPTURE_BYTES;
    __u64 actual_u64 = (__u64)actual;
    __u32 captured = actual_u64 < limit ? (__u32)actual_u64 : limit;
    if (bpf_probe_read_user(event->data, captured, (const void *)buffer) < 0) {
        bpf_ringbuf_discard(event, 0);
        return;
    }
    event->event_type = event_type;
    event->direction = direction;
    event->source = source;
    event->connection_key = connection_key;
    event->fd = fd;
    event->bytes = actual_u64;
    event->result = actual;
    event->original_len = requested > 0xffffffffULL ? 0xffffffffU : (__u32)requested;
    event->captured_len = captured;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void submit_chunk(
    __u64 buffer,
    __u64 requested,
    __s64 actual,
    __s32 fd,
    __u8 direction,
    __u8 source,
    __u64 connection_key,
    __u8 event_type)
{
    submit_chunk_limited(buffer, requested, actual, fd, direction, source,
                         connection_key, event_type, capture_bytes);
}

static __always_inline void submit_vector_chunks(
    __u64 pointer,
    __u64 count_hint,
    __u8 is_msghdr,
    __s64 actual,
    __s32 fd,
    __u8 direction,
    __u8 source,
    __u64 connection_key,
    __u8 event_type)
{
    if (actual <= 0 || !pointer)
        return;
    struct user_iovec *user_iov = (struct user_iovec *)pointer;
    __u64 iov_count = count_hint;
    if (is_msghdr) {
        struct user_msghdr message = {};
        if (bpf_probe_read_user(&message, sizeof(message), (const void *)pointer) < 0)
            return;
        if (message.msg_iovlen == 0 || !message.msg_iov)
            return;
        user_iov = message.msg_iov;
        iov_count = message.msg_iovlen;
    }
    __u64 remaining = (__u64)actual;
    __u32 budget = capture_bytes;
    if (budget > MAX_CAPTURE_BYTES)
        budget = MAX_CAPTURE_BYTES;
#pragma unroll
    for (int index = 0; index < MAX_VECTOR_CHUNKS; index++) {
        if ((__u64)index >= iov_count || remaining == 0 || budget == 0)
            break;
        struct user_iovec iov = {};
        if (bpf_probe_read_user(&iov, sizeof(iov), &user_iov[index]) < 0)
            break;
        __u64 segment = remaining < iov.iov_len ? remaining : iov.iov_len;
        if (segment == 0)
            continue;
        __u32 copied = segment < budget ? (__u32)segment : budget;
        __u64 remaining_after = remaining - segment;
        __u32 budget_after = budget - copied;
        __u64 reported_segment = segment;
        if (remaining_after > 0 &&
            (budget_after == 0 || index == MAX_VECTOR_CHUNKS - 1) &&
            reported_segment <= copied)
            reported_segment = (__u64)copied + 1;
        submit_chunk_limited((__u64)iov.iov_base, iov.iov_len, reported_segment, fd,
                             direction, source, connection_key, event_type, copied);
        remaining = remaining_after;
        budget = budget_after;
        if (reported_segment > copied)
            break;
    }
}

static __always_inline void remember_read(
    __u64 pid_tgid,
    __u64 buffer,
    __u64 requested,
    __s32 fd,
    __u8 source,
    __u8 vector_kind,
    __u8 is_ex,
    __u8 direction,
    __u8 is_network,
    __u64 connection_key,
    __u64 length_pointer)
{
    struct pending_read pending = {
        .buffer = buffer,
        .length_pointer = length_pointer,
        .requested = requested,
        .connection_key = connection_key,
        .fd = fd,
        .source = source,
        .vector_kind = vector_kind,
        .is_ex = is_ex,
        .direction = direction,
        .is_network = is_network,
    };
    bpf_map_update_elem(&pending_reads, &pid_tgid, &pending, BPF_ANY);
}

static __always_inline void start_latency(__u64 pid_tgid, __s32 fd, __u64 requested, __u8 operation)
{
    struct syscall_start start = {
        .started_ns = bpf_ktime_get_ns(),
        .requested = requested,
        .fd = fd,
        .operation = operation,
    };
    bpf_map_update_elem(&syscall_starts, &pid_tgid, &start, BPF_ANY);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!is_target_tgid(tgid))
        return 0;
    __u32 pid = (__u32)pid_tgid;
    bpf_map_update_elem(&target_threads, &pid, &tgid, BPF_ANY);
    if (bpf_map_lookup_elem(&tls_depth, &pid_tgid))
        return 0;

    __s32 fd = (__s32)ctx->args[0];
    switch (ctx->id) {
    case SYS_WRITE:
    case SYS_SENDTO:
        remember_read(pid_tgid, ctx->args[1], ctx->args[2], fd,
                      SOURCE_SYSCALL, 0, 0, DIRECTION_OUTBOUND,
                      0, (__u64)(__u32)fd, 0);
        break;
    case SYS_READ:
    case SYS_RECVFROM:
        remember_read(pid_tgid, ctx->args[1], ctx->args[2], fd,
                      SOURCE_SYSCALL, 0, 0, DIRECTION_INBOUND,
                      0, (__u64)(__u32)fd, 0);
        break;
    case SYS_WRITEV:
        remember_read(pid_tgid, ctx->args[1], ctx->args[2], fd,
                      SOURCE_SYSCALL, 1, 0, DIRECTION_OUTBOUND,
                      0, (__u64)(__u32)fd, 0);
        break;
    case SYS_SENDMSG:
        remember_read(pid_tgid, ctx->args[1], ctx->args[2], fd,
                      SOURCE_SYSCALL, 2, 0, DIRECTION_OUTBOUND,
                      0, (__u64)(__u32)fd, 0);
        break;
    case SYS_READV:
        remember_read(pid_tgid, ctx->args[1], ctx->args[2], fd,
                      SOURCE_SYSCALL, 1, 0, DIRECTION_INBOUND,
                      0, (__u64)(__u32)fd, 0);
        break;
    case SYS_RECVMSG:
        remember_read(pid_tgid, ctx->args[1], ctx->args[2], fd,
                      SOURCE_SYSCALL, 2, 0, DIRECTION_INBOUND,
                      0, (__u64)(__u32)fd, 0);
        break;
    case SYS_PREAD64:
        start_latency(pid_tgid, fd, ctx->args[2], OP_PREAD);
        break;
    case SYS_PWRITE64:
        start_latency(pid_tgid, fd, ctx->args[2], OP_PWRITE);
        break;
    case SYS_FSYNC:
        start_latency(pid_tgid, fd, 0, OP_FSYNC);
        break;
    case SYS_FDATASYNC:
        start_latency(pid_tgid, fd, 0, OP_FDATASYNC);
        break;
    case SYS_OPENAT:
        start_latency(pid_tgid, -1, 0, OP_OPENAT);
        break;
    default:
        break;
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!is_target_tgid(tgid))
        return 0;
    if (bpf_map_lookup_elem(&tls_depth, &pid_tgid))
        return 0;

    struct pending_read *pending = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    if (pending && (ctx->id == SYS_READ || ctx->id == SYS_RECVFROM ||
                    ctx->id == SYS_READV || ctx->id == SYS_RECVMSG ||
                    ctx->id == SYS_WRITE || ctx->id == SYS_SENDTO ||
                    ctx->id == SYS_WRITEV || ctx->id == SYS_SENDMSG)) {
        struct pending_read copy = *pending;
        bpf_map_delete_elem(&pending_reads, &pid_tgid);
        if (copy.vector_kind) {
            if (copy.is_network)
                submit_vector_chunks(copy.buffer, copy.requested,
                                     copy.vector_kind == 2, ctx->ret, copy.fd,
                                     copy.direction, copy.source, copy.connection_key,
                                     copy.protocol ? EVENT_DNS_CHUNK : EVENT_IO_CHUNK);
        } else {
            __s64 actual = ctx->ret;
            if (actual > 0 && (__u64)actual > copy.requested)
                actual = copy.requested;
            if (copy.is_network)
                submit_chunk(copy.buffer, copy.requested, actual, copy.fd,
                             copy.direction, copy.source, copy.connection_key,
                             copy.protocol ? EVENT_DNS_CHUNK : EVENT_IO_CHUNK);
        }
    }

    struct syscall_start *start = bpf_map_lookup_elem(&syscall_starts, &pid_tgid);
    if (start && (ctx->id == SYS_PREAD64 || ctx->id == SYS_PWRITE64 ||
                  ctx->id == SYS_FSYNC || ctx->id == SYS_FDATASYNC ||
                  ctx->id == SYS_OPENAT)) {
        struct syscall_start copy = *start;
        bpf_map_delete_elem(&syscall_starts, &pid_tgid);
        struct kernel_event *event = reserve_event();
        if (!event)
            return 0;
        event->event_type = EVENT_SYSCALL_LATENCY;
        event->source = SOURCE_KERNEL;
        event->operation = copy.operation;
        event->fd = copy.fd;
        event->duration_ns = bpf_ktime_get_ns() - copy.started_ns;
        event->bytes = copy.requested;
        event->result = ctx->ret;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

static __always_inline int ssl_enter(struct pt_regs *ctx, __u8 direction, __u8 is_ex)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!is_target_tgid(tgid))
        return 0;
    __u8 one = 1;
    bpf_map_update_elem(&tls_depth, &pid_tgid, &one, BPF_ANY);
    __u64 ssl = PT_REGS_PARM1(ctx);
    __u64 buffer = PT_REGS_PARM2(ctx);
    __u64 requested = PT_REGS_PARM3(ctx);
    __u64 length_pointer = is_ex ? PT_REGS_PARM4(ctx) : 0;
    __s32 fd = -1;
    __s32 *known_fd = bpf_map_lookup_elem(&ssl_fds, &ssl);
    if (known_fd)
        fd = *known_fd;
    __u64 connection_key = fd >= 0 ? (__u64)(__u32)fd : ssl;
    remember_read(pid_tgid, buffer, requested, fd, SOURCE_OPENSSL,
                  0, is_ex, direction, 1, connection_key, length_pointer);
    return 0;
}

static __always_inline int ssl_exit(struct pt_regs *ctx, __u8 direction)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_read *pending = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    bpf_map_delete_elem(&tls_depth, &pid_tgid);
    if (!pending)
        return 0;
    struct pending_read copy = *pending;
    bpf_map_delete_elem(&pending_reads, &pid_tgid);
    __s64 result = PT_REGS_RC(ctx);
    __s64 actual = result;
    if (copy.is_ex) {
        __u64 reported = 0;
        if (result == 1 && copy.length_pointer &&
            bpf_probe_read_user(&reported, sizeof(reported), (const void *)copy.length_pointer) == 0)
            actual = reported;
        else
            actual = 0;
    }
    submit_chunk(copy.buffer, copy.requested, actual, copy.fd, direction,
                 SOURCE_OPENSSL, copy.connection_key, EVENT_IO_CHUNK);
    return 0;
}

SEC("uprobe")
int handle_ssl_set_fd(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!is_target_tgid(pid_tgid >> 32))
        return 0;
    __u64 ssl = PT_REGS_PARM1(ctx);
    __s32 fd = (__s32)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_fds, &ssl, &fd, BPF_ANY);
    return 0;
}

SEC("uprobe")
int handle_ssl_free(struct pt_regs *ctx)
{
    __u64 ssl = PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&ssl_fds, &ssl);
    return 0;
}

SEC("uprobe")
int handle_mutex_lock_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!is_target_tgid(pid_tgid >> 32))
        return 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&lock_starts, &pid_tgid, &now, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int handle_mutex_lock_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *started = bpf_map_lookup_elem(&lock_starts, &pid_tgid);
    if (!started)
        return 0;
    __u64 duration = bpf_ktime_get_ns() - *started;
    bpf_map_delete_elem(&lock_starts, &pid_tgid);
    if (duration < lock_wait_threshold_ns)
        return 0;
    struct kernel_event *event = reserve_event();
    if (!event)
        return 0;
    event->event_type = EVENT_PROFILE;
    event->source = SOURCE_USER_UPROBE;
    event->operation = OP_LOCK_WAIT;
    event->duration_ns = duration;
    event->result = PT_REGS_RC(ctx);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe")
int handle_ssl_read_enter(struct pt_regs *ctx)
{
    return ssl_enter(ctx, DIRECTION_INBOUND, 0);
}

SEC("uretprobe")
int handle_ssl_read_exit(struct pt_regs *ctx)
{
    return ssl_exit(ctx, DIRECTION_INBOUND);
}

SEC("uprobe")
int handle_ssl_write_enter(struct pt_regs *ctx)
{
    return ssl_enter(ctx, DIRECTION_OUTBOUND, 0);
}

SEC("uretprobe")
int handle_ssl_write_exit(struct pt_regs *ctx)
{
    return ssl_exit(ctx, DIRECTION_OUTBOUND);
}

SEC("uprobe")
int handle_ssl_read_ex_enter(struct pt_regs *ctx)
{
    return ssl_enter(ctx, DIRECTION_INBOUND, 1);
}

SEC("uretprobe")
int handle_ssl_read_ex_exit(struct pt_regs *ctx)
{
    return ssl_exit(ctx, DIRECTION_INBOUND);
}

SEC("uprobe")
int handle_ssl_write_ex_enter(struct pt_regs *ctx)
{
    return ssl_enter(ctx, DIRECTION_OUTBOUND, 1);
}

SEC("uretprobe")
int handle_ssl_write_ex_exit(struct pt_regs *ctx)
{
    return ssl_exit(ctx, DIRECTION_OUTBOUND);
}

static __always_inline __u64 mix_socket_word(__u64 hash, __u64 value)
{
    return (hash ^ value) * 1099511628211ULL;
}

static __always_inline __u64 socket_handle(struct sock *sk)
{
    /* Kernel socket addresses are stable for the object's lifetime and are
     * used only as in-kernel map keys; they never cross the ring buffer. */
    return (__u64)sk;
}

static __always_inline __u64 socket_connection_key(struct sock *sk)
{
    __u64 hash = 1469598103934665603ULL;
    hash = mix_socket_word(hash, BPF_CORE_READ(sk, __sk_common.skc_daddr));
    hash = mix_socket_word(hash, BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    hash = mix_socket_word(hash, BPF_CORE_READ(sk, __sk_common.skc_dport));
    hash = mix_socket_word(hash, BPF_CORE_READ(sk, __sk_common.skc_num));
    hash = mix_socket_word(hash, BPF_CORE_READ(sk, __sk_common.skc_family));
    struct in6_addr destination = {};
    struct in6_addr source = {};
    BPF_CORE_READ_INTO(&destination, sk, __sk_common.skc_v6_daddr);
    BPF_CORE_READ_INTO(&source, sk, __sk_common.skc_v6_rcv_saddr);
#pragma unroll
    for (int index = 0; index < 4; index++) {
        hash = mix_socket_word(hash, destination.in6_u.u6_addr32[index]);
        hash = mix_socket_word(hash, source.in6_u.u6_addr32[index]);
    }
    return hash ? hash : 1;
}

static __always_inline int mark_dns_socket(struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!is_target_tgid(pid_tgid >> 32))
        return 0;
    struct pending_read *pending = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    if (!pending)
        return 0;
    pending->connection_key = socket_connection_key(sk);
    pending->is_network = 1;
    pending->protocol = 1;
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk)
{
    return mark_dns_socket(sk);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recvmsg, struct sock *sk)
{
    return mark_dns_socket(sk);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(handle_udpv6_sendmsg, struct sock *sk)
{
    return mark_dns_socket(sk);
}

SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(handle_udpv6_recvmsg, struct sock *sk)
{
    return mark_dns_socket(sk);
}

static __always_inline int track_socket(struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!is_target_tgid(tgid))
        return 0;
    __u64 handle = socket_handle(sk);
    struct pending_read *pending = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    struct socket_owner *existing = bpf_map_lookup_elem(&tracked_sockets, &handle);
    struct socket_owner owner = {
        .connection_key = existing
            ? existing->connection_key
            : mix_socket_word(socket_connection_key(sk), bpf_ktime_get_ns()),
        .tgid = tgid,
        .fd = pending ? pending->fd : -1,
    };
    if (owner.fd < 0 && existing)
        owner.fd = existing->fd;
    if (handle)
        bpf_map_update_elem(&tracked_sockets, &handle, &owner, BPF_ANY);
    if (pending && handle)
        pending->connection_key = owner.connection_key;
    if (pending)
        pending->is_network = 1;
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk)
{
    return track_socket(sk);
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk)
{
    return track_socket(sk);
}

static __always_inline void submit_connection(struct sock *sk, __u8 operation, __u64 duration_ns)
{
    __u64 handle = socket_handle(sk);
    if (!handle)
        return;
    struct socket_owner *owner = bpf_map_lookup_elem(&tracked_sockets, &handle);
    if (!owner)
        return;
    struct socket_owner copy = *owner;
    struct kernel_event *event = reserve_event();
    if (!event)
        return;
    event->event_type = EVENT_CONNECTION;
    event->source = SOURCE_KERNEL;
    event->operation = operation;
    event->connection_key = copy.connection_key;
    event->duration_ns = duration_ns;
    event->pid = copy.tgid;
    event->tgid = copy.tgid;
    event->fd = copy.fd;
    bpf_ringbuf_submit(event, 0);
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!is_target_tgid(pid_tgid >> 32))
        return 0;
    track_socket(sk);
    __u64 handle = socket_handle(sk);
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&handshake_starts, &handle, &now, BPF_ANY);
    submit_connection(sk, OP_TCP_CONNECT, 0);
    return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(handle_tcp_state, struct sock *sk, int newstate)
{
    __u64 handle = socket_handle(sk);
    struct socket_owner *owner = bpf_map_lookup_elem(&tracked_sockets, &handle);
    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (!owner && local_port != mongodb_port)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    if (newstate == TCP_SYN_SENT_STATE || newstate == TCP_SYN_RECV_STATE) {
        bpf_map_update_elem(&handshake_starts, &handle, &now, BPF_ANY);
        return 0;
    }
    __u64 *started = bpf_map_lookup_elem(&handshake_starts, &handle);
    if (newstate == TCP_ESTABLISHED_STATE) {
        __u64 duration = started ? now - *started : 0;
        if (owner)
            submit_connection(sk, OP_TCP_HANDSHAKE, duration);
        else
            bpf_map_update_elem(&completed_handshakes, &handle, &duration, BPF_ANY);
        if (started)
            bpf_map_delete_elem(&handshake_starts, &handle);
    } else if (newstate == TCP_CLOSE_STATE) {
        __u8 *reset_seen = bpf_map_lookup_elem(&peer_resets_seen, &handle);
        int socket_error = BPF_CORE_READ(sk, sk_err);
        if (owner && !reset_seen && socket_error == ECONNRESET_CODE)
            submit_connection(sk, OP_TCP_RESET_RECEIVED, 0);
        if (owner && socket_error == ETIMEDOUT_CODE)
            submit_connection(sk, OP_TCP_TIMEOUT, started ? now - *started : 0);
        bpf_map_delete_elem(&peer_resets_seen, &handle);
        if (started) {
            bpf_map_delete_elem(&handshake_starts, &handle);
        }
        bpf_map_delete_elem(&completed_handshakes, &handle);
    }
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_tcp_accept, struct sock *sk)
{
    if (!sk)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!is_target_tgid(pid_tgid >> 32))
        return 0;
    track_socket(sk);
    submit_connection(sk, OP_TCP_ACCEPT, 0);
    __u64 handle = socket_handle(sk);
    __u64 *duration = bpf_map_lookup_elem(&completed_handshakes, &handle);
    if (duration) {
        submit_connection(sk, OP_TCP_HANDSHAKE, *duration);
        bpf_map_delete_elem(&completed_handshakes, &handle);
    } else
        submit_connection(sk, OP_TCP_HANDSHAKE, 0);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk)
{
    __u64 handle = socket_handle(sk);
    struct socket_owner *owner = bpf_map_lookup_elem(&tracked_sockets, &handle);
    bpf_map_delete_elem(&handshake_starts, &handle);
    bpf_map_delete_elem(&completed_handshakes, &handle);
    if (!owner)
        return 0;
    submit_connection(sk, OP_TCP_CLOSE, 0);
    bpf_map_delete_elem(&tracked_sockets, &handle);
    bpf_map_delete_elem(&rtt_last_emit, &handle);
    bpf_map_delete_elem(&peer_resets_seen, &handle);
    return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(handle_tcp_rtt, struct sock *sk)
{
    __u64 handle = socket_handle(sk);
    if (!bpf_map_lookup_elem(&tracked_sockets, &handle))
        return 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&rtt_last_emit, &handle);
    if (last && now - *last < rtt_sample_interval_ns)
        return 0;
    bpf_map_update_elem(&rtt_last_emit, &handle, &now, BPF_ANY);
    __u32 srtt_us = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us) >> 3;
    submit_connection(sk, OP_TCP_RTT, (__u64)srtt_us * 1000ULL);
    if (BPF_CORE_READ((struct tcp_sock *)sk, snd_wnd) == 0)
        submit_connection(sk, OP_TCP_ZERO_WINDOW, 0);
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(handle_tcp_retransmit, struct sock *sk, struct sk_buff *skb)
{
    __u64 handle = socket_handle(sk);
    if (!bpf_map_lookup_elem(&tracked_sockets, &handle))
        return 0;
    submit_connection(sk, OP_TCP_RETRANSMIT, 0);
    return 0;
}

SEC("kprobe/tcp_reset")
int BPF_KPROBE(handle_tcp_reset, struct sock *sk)
{
    __u64 handle = socket_handle(sk);
    if (bpf_map_lookup_elem(&tracked_sockets, &handle)) {
        submit_connection(sk, OP_TCP_RESET_RECEIVED, 0);
        __u8 seen = 1;
        bpf_map_update_elem(&peer_resets_seen, &handle, &seen, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/tcp_send_active_reset")
int BPF_KPROBE(handle_tcp_active_reset, struct sock *sk)
{
    __u64 handle = socket_handle(sk);
    if (bpf_map_lookup_elem(&tracked_sockets, &handle))
        submit_connection(sk, OP_TCP_RESET_SENT, 0);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 prev = ctx->prev_pid;
    __u32 next = ctx->next_pid;
    if (bpf_map_lookup_elem(&target_threads, &prev))
        bpf_map_update_elem(&offcpu_starts, &prev, &now, BPF_ANY);
    __u64 *started = bpf_map_lookup_elem(&offcpu_starts, &next);
    __u32 *tgid = bpf_map_lookup_elem(&target_threads, &next);
    if (!started || !tgid)
        return 0;
    __u64 duration = now - *started;
    bpf_map_delete_elem(&offcpu_starts, &next);
    if (duration < offcpu_threshold_ns)
        return 0;
    struct kernel_event *event = reserve_event();
    if (!event)
        return 0;
    event->event_type = EVENT_SYSCALL_LATENCY;
    event->source = SOURCE_KERNEL;
    event->operation = OP_OFFCPU;
    event->pid = next;
    event->tgid = *tgid;
    event->duration_ns = duration;
    __builtin_memcpy(event->comm, ctx->next_comm, TASK_COMM_LEN);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int is_mongodb_comm(char comm[TASK_COMM_LEN])
{
    return comm[0] == 'm' && comm[1] == 'o' && comm[2] == 'n' &&
           comm[3] == 'g' && comm[4] == 'o' &&
           ((comm[5] == 'd' && comm[6] == 0) ||
            (comm[5] == 's' && comm[6] == 0));
}

SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_template *ctx)
{
    char comm[TASK_COMM_LEN];
    if (bpf_get_current_comm(comm, sizeof(comm)) < 0 || !is_mongodb_comm(comm))
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    __u8 one = 1;
    bpf_map_update_elem(&target_tgids, &tgid, &one, BPF_ANY);
    bpf_map_update_elem(&target_threads, &pid, &tgid, BPF_ANY);
    struct kernel_event *event = reserve_event();
    if (!event)
        return 0;
    event->event_type = EVENT_PROCESS;
    event->source = SOURCE_KERNEL;
    event->operation = OP_PROCESS_EXEC;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    bpf_map_delete_elem(&target_threads, &pid);
    if (pid != tgid || !is_target_tgid(tgid))
        return 0;
    struct kernel_event *event = reserve_event();
    if (event) {
        event->event_type = EVENT_PROCESS;
        event->source = SOURCE_KERNEL;
        event->operation = OP_PROCESS_EXIT;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&target_tgids, &tgid);
    return 0;
}

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_page_fault_enter)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!is_target_tgid(pid_tgid >> 32))
        return 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&fault_starts, &pid_tgid, &now, BPF_ANY);
    return 0;
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(handle_page_fault_exit)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *started = bpf_map_lookup_elem(&fault_starts, &pid_tgid);
    if (!started)
        return 0;
    __u64 duration = bpf_ktime_get_ns() - *started;
    bpf_map_delete_elem(&fault_starts, &pid_tgid);
    if (duration < page_fault_threshold_ns)
        return 0;
    struct kernel_event *event = reserve_event();
    if (!event)
        return 0;
    event->event_type = EVENT_SYSCALL_LATENCY;
    event->source = SOURCE_KERNEL;
    event->operation = OP_PAGE_FAULT;
    event->duration_ns = duration;
    event->result = PT_REGS_RC(ctx);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("perf_event")
int handle_cpu_sample(struct bpf_perf_event_data *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!is_target_tgid(pid_tgid >> 32))
        return 0;
    struct kernel_event *event = reserve_event();
    if (!event)
        return 0;
    event->event_type = EVENT_PROFILE;
    event->source = SOURCE_PERF;
    event->operation = OP_CPU_SAMPLE;
    event->result = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    event->fd = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
