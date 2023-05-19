#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bpf.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

int trace_dma_alloc_coherent(struct pt_regs *ctx, struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t gfp)
{
    struct event_data data = {};
    data.dev = (uintptr_t)dev;
    data.size = size;
    data.dma_handle = (uintptr_t)dma_handle;
    data.gfp = gfp;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}