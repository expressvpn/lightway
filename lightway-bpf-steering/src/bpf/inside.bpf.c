// TUN queue steerer, attached with TUNSETSTEERINGEBPF.
//
// Must be BPF_PROG_TYPE_SOCKET_FILTER (drivers/net/tun.c:3017) and its return
// value is used as `ret % numqueues` (tun.c:558), so it returns a queue index.
//
// Unlike the outside program this inspects nothing: when ExpressLane is Active
// EVERY inside packet is offloaded, exactly as the kernel driver behaves. The
// control plane flips one map entry on state change, so falling back to DTLS
// is a single map write.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define QUEUE_CONTROL 0
#define QUEUE_ENGINE  1

// Single entry: non-zero means ExpressLane is Active and the engine owns the
// inside path. Device-wide, not per-session - a client has one connection.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} offload_active SEC(".maps");

// [0] = packets steered to the control queue, [1] = to the engine queue.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} inside_counts SEC(".maps");

SEC("socket")
int lw_steer(struct __sk_buff *skb)
{
    __u32 zero = 0;
    __u32 queue = QUEUE_CONTROL;

    __u32 *active = bpf_map_lookup_elem(&offload_active, &zero);
    if (active && *active)
        queue = QUEUE_ENGINE;

    __u64 *c = bpf_map_lookup_elem(&inside_counts, &queue);
    if (c)
        __sync_fetch_and_add(c, 1);

    return queue;
}

char _license[] SEC("license") = "GPL";
