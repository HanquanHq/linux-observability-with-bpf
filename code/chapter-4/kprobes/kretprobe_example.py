from bcc import BPF

bpf_source = """
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <uapi/linux/ptrace.h>

int ret_sys_execve(struct pt_regs *ctx) {
    int return_value;
    return_value = PT_REGS_RC(ctx);

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    bpf_trace_printk("program: %s, return: %d \\n", comm, return_value);
    return 0;
}
"""

bpf = BPF(text=bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
bpf.attach_kretprobe(event = execve_function, fn_name = "ret_sys_execve")
bpf.trace_print()
