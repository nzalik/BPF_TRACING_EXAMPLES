#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This is an example of tracing an event and printing custom fields.
# run in project examples directory with:
# sudo ./trace_fields.py"

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

prog = """
int hello(void *ctx) {
  bpf_trace_printk("Device well mount!\\n");
  return 0;
}
"""

prog2 = """
int hello2(void *ctx) {
  bpf_trace_printk("Good bye\\n");
  return 0;
}
"""

b = BPF(text=prog)
#b2 = BPF(text=prog2)
b.attach_kprobe(event="blk_start_request", fn_name="hello")
#b2.attach_kprobe(event=b.get_syscall_fnname("umount"), fn_name="hello2")

while 1:
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		(bytes_s, bflags_s, us_s) = msg.split()

		if int(bflags_s, 16) & REQ_WRITE:
			type_s = b"W"
		elif bytes_s == "0":	# see blk_fill_rwbs() for logic
			type_s = b"M"
		else:
			type_s = b"R"
		ms = float(int(us_s, 10)) / 1000

		printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
	except KeyboardInterrupt:
		exit()
