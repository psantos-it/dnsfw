#!/bin/bash
# monitor_cpu.sh

# Monitoramento de CPU para programas eBPF
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_bpf {
    @bpf_syscalls[comm] = count();
}

profile:hz:99 {
    @cpu_profile[comm] = count();
}

interval:s:1 {
    printf("Estatísticas de CPU para eBPF:\n");
    print(@bpf_syscalls);
    print(@cpu_profile);
    
    clear(@bpf_syscalls);
    clear(@cpu_profile);
}
'