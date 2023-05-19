#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

void trace_start(void *ctx) {
  bpf_trace_printk("executing program 1:");
}

void trace_completion(void *ctx) {
  bpf_trace_printk("executing program 2: Userspace");
}
""")

#b.attach_uprobe(name="c", sym="strlen", fn_name="trace_completion")
b.attach_uprobe(name="c", sym="mmap", fn_name="trace_completion")
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

b.trace_print()

