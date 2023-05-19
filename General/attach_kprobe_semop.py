from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sem.h>
#include <linux/ipc.h>
int hit_somop_enter(struct pt_regs *ctx, int semid, struct sembuf *sops, unsigned nsops) {

  bpf_trace_printk("Sem_Id= %d ", semid);
  bpf_trace_printk("Entering: sops->sem_op = %d   sops->sem_num = %d  sops->sem_flg = %d",sops[0].sem_num, sops[0].sem_op, sops[0].sem_flg);

  return 0;
}

int ret_somop_enter(struct pt_regs *ctx, struct sembuf *sops, int semid, unsigned nsops) {

  u32 pid = bpf_get_current_pid_tgid();
  
  bpf_trace_printk("Exiting: PID=%d",&pid);
  return 0;
}
"""


bpf = BPF(text=bpf_source)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("semop"), fn_name="hit_somop_enter")
bpf.attach_kretprobe(event=bpf.get_syscall_fnname("semop"), fn_name="ret_somop_enter")

bpf.trace_print()