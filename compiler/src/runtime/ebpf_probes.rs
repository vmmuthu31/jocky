/// eBPF probe C source emitter for Linux kernel telemetry.
///
/// Emits compilable BPF C source (via libbpf/BCC skeleton) for three probes:
///   • tracepoint:sched:sched_process_exec   — process execution events
///   • kprobe:vfs_open (sys_open)            — file open events
///   • kprobe:tcp_connect                    — outbound TCP connections
///
/// The emitted C is meant to be compiled with `clang -target bpf -O2`
/// and loaded via libbpf's skeleton API.  The forensic runtime calls
/// `jocky_ebpf_load()` which dlopen's the libbpf skeleton object.

pub struct EbpfProbeEmitter;

impl EbpfProbeEmitter {
    /// Emit the BPF C source for all three probes.
    pub fn emit_bpf_c_source() -> String {
        r#"// JOCKY eBPF forensic probes — NTRO Hackathon 26148
// Compile: clang -target bpf -O2 -g jocky_probes.bpf.c -o jocky_probes.bpf.o
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>
#include <linux/fs.h>

// ─── Ring-buffer for event output ────────────────────────────────────────────
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB ring buffer
} jocky_events SEC(".maps");

// ─── Event types ─────────────────────────────────────────────────────────────
#define JOCKY_EVT_EXEC    1
#define JOCKY_EVT_OPEN    2
#define JOCKY_EVT_CONNECT 3

struct jocky_event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    char  comm[16];
    char  detail[256]; // filename or IP:port
};

// ─── Probe 1: process execution ──────────────────────────────────────────────
SEC("tp/sched/sched_process_exec")
int jocky_exec_probe(struct trace_event_raw_sched_process_exec *ctx) {
    struct jocky_event *e = bpf_ringbuf_reserve(&jocky_events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = JOCKY_EVT_EXEC;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_str(e->detail, sizeof(e->detail), ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Probe 2: file open ───────────────────────────────────────────────────────
SEC("kprobe/vfs_open")
int jocky_open_probe(struct pt_regs *ctx) {
    struct jocky_event *e = bpf_ringbuf_reserve(&jocky_events, sizeof(*e), 0);
    if (!e) return 0;

    struct path *p = (struct path *)PT_REGS_PARM1(ctx);
    e->type = JOCKY_EVT_OPEN;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct dentry *dentry;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &p->dentry);
    bpf_probe_read_kernel_str(e->detail, sizeof(e->detail), &dentry->d_iname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Probe 3: TCP connect ─────────────────────────────────────────────────────
SEC("kprobe/tcp_connect")
int jocky_tcp_probe(struct pt_regs *ctx) {
    struct jocky_event *e = bpf_ringbuf_reserve(&jocky_events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = JOCKY_EVT_CONNECT;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __be32 daddr;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    __be16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    __builtin_snprintf(e->detail, sizeof(e->detail), "%pI4:%d", &daddr, (int)__builtin_bswap16(dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
"#.to_string()
    }

    /// Emit the userspace loader skeleton (C) that opens/loads the BPF object.
    pub fn emit_loader_c() -> String {
        r#"// JOCKY eBPF loader (userspace skeleton)
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int jocky_ebpf_load(const char *bpf_obj_path) {
    struct bpf_object *obj = bpf_object__open(bpf_obj_path);
    if (!obj) { perror("bpf_object__open"); return -1; }
    if (bpf_object__load(obj)) { perror("bpf_object__load"); return -1; }
    // Attach all programs
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }
    return 0;
}
"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_source_has_all_three_probes() {
        let src = EbpfProbeEmitter::emit_bpf_c_source();
        assert!(src.contains("jocky_exec_probe"),    "exec probe required");
        assert!(src.contains("jocky_open_probe"),    "open probe required");
        assert!(src.contains("jocky_tcp_probe"),     "tcp probe required");
    }

    #[test]
    fn test_bpf_source_uses_ringbuf() {
        let src = EbpfProbeEmitter::emit_bpf_c_source();
        assert!(src.contains("BPF_MAP_TYPE_RINGBUF"), "must use ring buffer for perf");
    }

    #[test]
    fn test_license_section_present() {
        let src = EbpfProbeEmitter::emit_bpf_c_source();
        assert!(src.contains("SEC(\"license\")"), "BPF programs require license section");
        assert!(src.contains("GPL"), "GPL required for kernel helpers");
    }

    #[test]
    fn test_loader_calls_attach() {
        let loader = EbpfProbeEmitter::emit_loader_c();
        assert!(loader.contains("bpf_program__attach"), "must attach programs");
    }
}
