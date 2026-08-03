// SK_REUSEPORT splitter: ExpressLane datagrams to the engine socket,
// everything else to the control-plane socket.
//
// sk_reuseport_md.data begins at the UDP header (uapi/linux/bpf.h:6159-6173),
// so the Lightway payload starts at data + 8 and the expresslane_data flag
// sits at data + 13.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define UDP_HDR_LEN 8
#define LW_MAGIC_0 'H'
#define LW_MAGIC_1 'e'
#define LW_FLAG_OFF 5

#define IDX_CONTROL 0
#define IDX_ENGINE  1
#define IDX_FAILED  2

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} socks SEC(".maps");

// [0] = delivered to the control plane, [1] = delivered to the engine,
// [2] = selection failed (e.g. socks[idx] has no socket registered yet, a
// startup race) and the kernel fell back to hash-based delivery instead.
// Counts the outcome of bpf_sk_select_reuseport, not the classifier's
// intent, so this is ground truth for "did it actually offload" reported by
// the kernel rather than by either process.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} outside_counts SEC(".maps");

SEC("sk_reuseport")
int lw_split(struct sk_reuseport_md *md)
{
    __u8 *p = (__u8 *)md->data + UDP_HDR_LEN;
    __u32 idx = IDX_CONTROL;

    // Anything too short to classify is not ExpressLane; let the control
    // plane decide what it is.
    if ((void *)(p + LW_FLAG_OFF + 1) <= md->data_end &&
        p[0] == LW_MAGIC_0 && p[1] == LW_MAGIC_1 && p[LW_FLAG_OFF] != 0)
        idx = IDX_ENGINE;

    __u32 outcome = idx;
    if (bpf_sk_select_reuseport(md, &socks, &idx, 0) != 0)
        outcome = IDX_FAILED;

    __u64 *c = bpf_map_lookup_elem(&outside_counts, &outcome);
    if (c)
        __sync_fetch_and_add(c, 1);

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
