# the idea here is to see if some programs are requesting physical memoryview
# The next step will be to ensure ourselves that that memory were asked to performed DMA transactions

# ioremap() function is used to map the physical addres of an I/O device to
# the kernel virtual address. Kernel creates a page table
# i.e mapping of virtual address to the physical address requested.
# When we do iounmap() this mapping is destroyed.


from bcc import BPF

# define BPF program
prog = """
int hello(void *ctx) {
    bpf_trace_printk("Invokation of ioremap !\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("ioremap"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
