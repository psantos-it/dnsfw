# DNS Firewall XDP
DNS Firewall desenvolvido em C utilizando o framework eBPF/XDP.<br>

A solução é composta por dois componentes: um programa que é executado no espaço do usuário (**dnsfw_xdp**), atuando como o plano de controle, e outro programa que opera no plano de dados programáveis do espaço do kernel.<br>

O programa no espaço do kernel cria dois mapas do tipo BPF_MAP_TYPE_HASH: um para armazenar a lista de domínios maliciosos (**domain_map**) e outro para registrar estatísticas dos domínios bloqueados (**query_stats_map**).

## Ambiente

Sistema operacional Red Hat 9.5 e versão do Kernel 5.14.0.<br>
Servidor DNS BIND 9.16.23.

## Pré-requisitos
Pacotes utilizados para compilar o código-fonte.
```bash
dnf -y install clang make gcc glibc-devel.i686 libbpf-devel
dnf -y install sysstat
dnf -y install git
``` 
Pacote utilizado para monitorar o consumo de CPU.
```bash
dnf -y install sysstat
dnf -y install git
``` 
Git para clonar o repositório do código-fonte
```bash
dnf -y install git
git clone git@github.com:psantos-it/dnsfw.git
``` 
Ferramenta para debug dos programas eBPF<br>
    <pre>https://github.com/libbpf/bpftool</pre>

Comandos úteis para debug do programa eBPF
```bash
bpftool prog show
bpftool map show
bpftool map dump name xdp_domains_map
cat /sys/kernel/debug/tracing/trace_pipe
``` 

Verificar se o firewall está ativado, se estiver desativar.
```bash
systemctl status firewalld
systemctl stop firewalld # desativa o firewall
systemctl status firewalld
```
## Instalando e rodando
Após clonar o repositório editar o arquivo Makefile para ajustar a interface que será realizado o attach do programa.
```bash
cd dnsfw
make
make run
```
Para remover o attach após a execução:
```bash
make clean
```
