#!/usr/bin/python

from __future__ import print_function
import os
import re
import sys
import csv
import io
import time

from base64 import b64encode
from bcc import BPF
from bcc.utils import printb
import bcc.utils as utils
from simhash import Simhash
from ctypes import c_int


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <asm/unistd.h>

#define ARGSIZE  256

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[ARGSIZE];
    u32 syscall;
    // registers
    u64 ip, sp, fp, cred;
    u64 ns;
};

struct data_long_t {
    char execve_arg0[ARGSIZE];
    char execve_arg1[ARGSIZE];
    char execve_arg2[ARGSIZE];
    char execve_arg3[ARGSIZE];
    u64 execve_argc;
};

BPF_ARRAY(events_data_long, struct data_long_t, 1);
BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct data_t data = {};
    struct task_struct *task;

    data.ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.ip = PT_REGS_IP(ctx);
    data.sp = (u64) task->stack - PT_REGS_SP(ctx);
    data.fp = (u64) task->stack - PT_REGS_FP(ctx);
    data.syscall = __NR_execve;
    data.cred = bpf_get_current_uid_gid();

    int zero = 0;
    struct data_long_t* ldata = events_data_long.lookup(&zero);
    if (ldata) {
        ldata->execve_argc = 0;
        const char *p = NULL;
        
        bpf_probe_read(&p, sizeof(p), &__argv[0]);
        if (p) { bpf_probe_read(ldata->execve_arg0, sizeof(ldata->execve_arg0), p); ldata->execve_argc++; } else { goto out; }
        p = NULL;
        bpf_probe_read(&p, sizeof(p), &__argv[1]);
        if (p) { bpf_probe_read(ldata->execve_arg1, sizeof(ldata->execve_arg1), p); ldata->execve_argc++; } else { goto out; }
        p = NULL;
        bpf_probe_read(&p, sizeof(p), &__argv[2]);
        if (p) { bpf_probe_read(ldata->execve_arg2, sizeof(ldata->execve_arg2), p); ldata->execve_argc++; } else { goto out; }
        p = NULL;
        bpf_probe_read(&p, sizeof(p), &__argv[3]);
        if (p) { bpf_probe_read(ldata->execve_arg3, sizeof(ldata->execve_arg3), p); ldata->execve_argc++; } else { goto out; }
    }
out:

    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}

"""

# initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

writer = csv.writer(sys.stdout, delimiter=';')

def get_exe_best_effort(pid):
    try:
        return os.readlink("/proc/%d/exe" % pid)
    except OSError:
        return "<unknown%d>" % pid

# process event
def print_event(cpu, data, size):
    t = time.time()
    event = b["events"].event(data)
    data = b["events_data_long"][c_int(0)]
    args = [data.execve_arg0]
    argc = data.execve_argc 
    if argc >= 2:
        args.append(data.execve_arg1)
    if argc >= 3:
        args.append(data.execve_arg2)
    if argc >= 4:
        args.append(data.execve_arg3)

    ppid = int(event.ppid)
    exe = get_exe_best_effort(event.pid)
    pexe = get_exe_best_effort(ppid)

    values = [
        str(event.ns),
        Simhash(exe).value,
        Simhash(pexe).value,
        Simhash(event.comm).value,
        event.syscall,
        event.cred,
        event.pid,
        event.ppid,
        event.ip,
        event.fp,
        event.sp,
        Simhash(args).value,
        str(b64encode("annotation:%s_%s_%s_%s_%s" % (str(t), exe, pexe, event.comm, args)))
    ]
    
    writer.writerow(values)

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
