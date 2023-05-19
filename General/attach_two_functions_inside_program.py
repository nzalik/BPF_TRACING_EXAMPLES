# We are tracing which app is calling a clone and which one is using execve
# The mush important here is that we want to attach to our bpf iinstance a function
# depending on the result of the helper get_kprobe_functions
from bcc import BPF

bpf_source = """
int do_sys_execve(void *ctx) { 
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_trace_printk("executing program related to execve: %s", comm);
  return 0;
}
"""

bpf_source2 = """
int trace_start(void *ctx) { 
  u64 ts = bpf_get_current_uid_gid();
  bpf_trace_printk("executing program related to dma: %d", ts);
  return 0;
}
"""

if BPF.get_kprobe_functions(b'blk_start_request'):
    bpf = BPF(text = bpf_source)
    execve_function = bpf.get_syscall_fnname("execve")		
    bpf.attach_kprobe(event = execve_function, fn_name = "do_sys_execve")
else:
    bpf = BPF(text = bpf_source2)
    clone_function = bpf.get_syscall_fnname("clone")	
    bpf.attach_kprobe(event=clone_function, fn_name="trace_start")
	
print("Tracing which function is calling execve")

# When you leave it like this the trace_print() function will return all from the bfp program
# If you want to select specific fields inside the output of the bpf program you can comment this line
# and reduce or add field to retrieve from the trace_fields() function
bpf.trace_print()
""" while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg)) """