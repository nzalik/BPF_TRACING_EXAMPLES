from bcc import BPF

bpf_program = BPF(text=open("dma_alloc_coherent_trace.c").read())
bpf_program.attach_kprobe(event="dma_alloc_coherent", fn_name="trace_dma_alloc_coherent")

def print_event(cpu, data, size):
    event = bpf_program["events"].event(data)
    print("dev=%d size=%d dma_handle=%d gfp=%d" % (event.dev, event.size, event.dma_handle, event.gfp))

bpf_program["events"].open_perf_buffer(print_event)
while True:
    bpf_program.perf_buffer_poll()