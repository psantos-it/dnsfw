#!/bin/bash

# Benchmark de Desempenho para Programa XDP de Filtragem DNS

# Variáveis de Configuração
INTERFACE="enp9s0"  # Substitua pela sua interface de rede
DURATION=60  # Duração do teste em segundos
OUTPUT_DIR="bpf_perf_$(date +%Y%m%d_%H%M%S)"

# Criar diretório de saída
mkdir -p $OUTPUT_DIR

# Função para coletar métricas
collect_metrics() {
    echo "Iniciando coleta de métricas..."
    
    # Estatísticas de CPU
    echo "Estatísticas de CPU:"
    mpstat 1 $DURATION > $OUTPUT_DIR/cpu_stats.txt &

    # Monitoramento de mapas BPF
    echo "Monitoramento de Mapas BPF:"
    while [ $DURATION -gt 0 ]; do
        sudo bpftool map dump pinned /sys/fs/bpf/xdp_domain_map >> $OUTPUT_DIR/domain_map_dump.txt
        sudo bpftool map dump pinned /sys/fs/bpf/xdp_query_stats_map >> $OUTPUT_DIR/query_stats_dump.txt
        sleep 5
        DURATION=$((DURATION - 5))
    done

    # Perfil de Performance
    echo "Gerando perfil de performance..."
    sudo perf record -g -F 99 -p $(pgrep -f dnsfw_xdp) -o $OUTPUT_DIR/perf.data

    # Relatório de Performance
    sudo perf report -i $OUTPUT_DIR/perf.data > $OUTPUT_DIR/perf_report.txt
}

# Iniciar benchmark
collect_metrics

# Análise final
echo "Benchmark concluído. Resultados em $OUTPUT_DIR"
echo "Arquivos gerados:"
ls $OUTPUT_DIR