#!/usr/bin/env python
# coding=utf-8
from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse
from collections import namedtuple, defaultdict
from threading import Thread, currentThread, Lock

# 选项参数检错
def range_check(string):
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value
# 帮助信息的example
examples = """examples:
    ./flow          # trace send/recv flow by host 
    ./flow -p 100   # only trace PID 100
"""
# 使用 python 中的 argparse类 定义选项
parser = argparse.ArgumentParser(
    description = "Summarize send and recv flow by host",
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog = examples
)
parser.add_argument("-p", "--pid", 
    help = "Trace this pid only")
parser.add_argument("interval", nargs="?", default=1, type=range_check,
    help = "output interval, in second (default 1)")
parser.add_argument("count", nargs="?", default=-1, type=range_check,
    help="number of outputs")
args = parser.parse_args()

bpf_program = """
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

/*必要的头文件*/
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

/*定义BPF_HASH中的值*/
struct ipv4_key_t {
    u32 pid;
};

/*定义两个哈希表，分别以ipv4中发送和接收数据包的进程pid作为关键字*/
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

/*探测内核中的 tcp_sendmsg 函数 */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    /*获取当前进程的pid*/
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    /*此部分在python里处理，用于替换特定功能的c语句*/
    FILTER_PID
    /*获取网络协议的套接字类型*/
    u16 family = sk->__sk_common.skc_family;
    /*判断是否是IPv4*/
    if (family == AF_INET) {
        /*将当前进程的pid放入ipv4_key结构体中
          作为ipv4_send_bytes哈希表的关键字*/
        struct ipv4_key_t ipv4_key = {.pid = pid};
        /*将size的值作为哈希表的值进行累加*/
        ipv4_send_bytes.increment(ipv4_key, size);
    }
    return 0;
}

/*探测内核中的 tcp_cleanup_rbuf 函数 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    /*获取当前进程的pid*/
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    /*此部分在python里处理，用于替换特定功能的c语句*/
    FILTER_PID
    /*获取网络协议的套接字类型*/
    u16 family = sk->__sk_common.skc_family;
    u64 *val, zero =0;
    /*检错*/
    if (copied <= 0)
        return 0;
    /*判断是否是IPv4*/
    if (family == AF_INET) {
        /*将当前进程的pid放入ipv4_key结构体中
          作为ipv4_send_bytes哈希表的关键字*/
        struct ipv4_key_t ipv4_key = {.pid = pid};
        /*将copied的值作为哈希表的值进行累加*/
        ipv4_recv_bytes.increment(ipv4_key, copied);
    }
    return 0;
}
"""

if args.pid:
    bpf_program = bpf_program.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_program = bpf_program.replace('FILTER_PID','')


# 获取进程名称
def pid_to_comm(pid):
    try:
        temp_cgroup = open("/proc/%s/cgroup" % pid, "r").read().rstrip()
        if 'cri-containerd-156ec432c785a7af6d85f94a77d747a5bf013167daf6ea0f750f391e991d9226.scope' in temp_cgroup:
            print("=============="+str(pid)+"=================")
        comm = open("/proc/%s/comm" % pid, "r").read().rstrip()
        return comm
    except IOError:
        return str(pid)
# 获取pid
SessionKey = namedtuple('Session',['pid'])
def get_ipv4_session_key(k):
    return SessionKey(pid=k.pid)

# init bpf
b = BPF(text=bpf_program)
ipv4_send_bytes = b["ipv4_send_bytes"]
# print(type(ipv4_send_bytes)) <class 'bcc.table.HashTable'>
ipv4_recv_bytes = b["ipv4_recv_bytes"]

# header
print("%-10s %-12s %-10s %-10s %-10s %-10s %-10s" % ("PID", "COMM", "RX_KB", "TX_KB", "RXSUM_KB", "TXSUM_KB", "SUM_KB"))

# output
#初始化变量
sumrecv = 0
sumsend = 0
sum_kb = 0
i = 0
exiting = False

print(args.interval)

while i != args.count and not exiting:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True
        
    ipv4_throughput = defaultdict(lambda:[0,0])
    for k, v in ipv4_send_bytes.items():
        key=get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value
    # ipv4_send_bytes.clear()

    for k,v in ipv4_recv_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value
    # ipv4_recv_bytes.clear()
    print(len(ipv4_throughput))
    if ipv4_throughput:
        for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
            key=lambda kv: sum(kv[1]),
            reverse=True):
            recv_bytes = int(recv_bytes) #/1024
            send_bytes = int(send_bytes) #/1024
            sumrecv += recv_bytes
            sumsend += send_bytes
            sum_kb = sumrecv + sumsend
            print("%-10d %-12.12s %-10d %-10d %-10d %-10d %-10d" % (k.pid, pid_to_comm(k.pid), recv_bytes, send_bytes, sumrecv, sumsend, sum_kb))
    i += 1
    print("=============================curl=============================")

