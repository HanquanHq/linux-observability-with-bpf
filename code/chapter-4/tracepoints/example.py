from bcc import BPF

bpf_source = """
int trace_bpf_prog_load() {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("%s command is starting a softirq_entry\\n", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "irq:softirq_entry", fn_name = "trace_bpf_prog_load")
bpf.trace_print()
