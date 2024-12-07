#!/bin/bash
# monitor_cpu.sh

# Monitoramento de CPU para programas eBPF
sudo bpftrace -e '

profile:hz:99 {
    @cpu_profile[comm] = count();
    
}

interval:s:1 {
    printf("Estatísticas de CPU para eBPF:\n");

    print(@cpu_profile);
    

    clear(@cpu_profile);
}
'