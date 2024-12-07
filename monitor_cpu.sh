#!/bin/bash
# monitor_cpu.sh

# Verifica se um PID foi fornecido
if [ $# -eq 0 ]; then
    echo "Uso: $0 <PID>"
    echo "Exemplo: $0 1234"
    exit 1
fi

TARGET_PID=$1

sudo bpftrace -e '
BEGIN {
    printf("Monitoramento de CPU para PID %d\n", $1);
    printf("Legenda:\n");
    printf("- Amostras de CPU: Frequência de execução do processo\n");
    printf("- Resolução: 99 amostras por segundo\n\n");
}

profile:hz:99 / pid == $1 / {
    @cpu_samples[comm] = count();
    @cpu_stacks[stacks] = count();
}

interval:s:1 {
    printf("Estatísticas de CPU - %s (PID %d)\n", comm, $1);
    
    printf("Amostras de CPU:\n");
    print(@cpu_samples);
    
    printf("\nTop 3 Pilhas de Execução:\n");
    print(@cpu_stacks, 3);
    
    clear(@cpu_samples);
    clear(@cpu_stacks);
}

END {
    clear(@cpu_samples);
    clear(@cpu_stacks);
}
' $TARGET_PID