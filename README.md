# DNS Firewall XDP
DNS Firewall desenvolvido em C utilizando o framework eBPF/XDP.<br>

A solução é composta por dois componentes: um programa que é executado no espaço do usuário (**dnsfw_xdp**), atuando como o plano de controle, e outro programa que opera no plano de dados programáveis do espaço do kernel.<br>

O programa no espaço do kernel cria dois mapas do tipo BPF_MAP_TYPE_HASH: um para armazenar a lista de domínios maliciosos (**domain_map**) e outro para registrar estatísticas dos domínios bloqueados (**query_stats_map**).

## Ambiente

Sistema operacional Red Hat 9.5 e versão do Kernel 5.14.0.<br>
Servidor DNS BIND 9.16.23.
