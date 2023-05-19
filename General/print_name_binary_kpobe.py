from bcc import BPF

bpf_source = """
int do_sys_execve(void *ctx) { 
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_trace_printk("executing program: %s", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)	
execve_function = bpf.get_syscall_fnname("execve")		
bpf.attach_kprobe(event = execve_function, fn_name = "do_sys_execve")	
print("Tracing which function is calling execve")

# When you leave it like this the trace_print() function will return all from the bfp program
# If you want to select specific fields inside the output of the bpf program you can comment this line
# and reduce or add field to retrieve from the trace_fields() function
bpf.trace_print()
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))