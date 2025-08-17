KERN_TARGETS  := dnsfw_xdp.kern
USER_TARGETS := dnsfw_xdp

DEV=enp2s0

all:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include -I/usr/include/x86_64-linux-gnu -I/usr/include/x86_64-linux-gnu/asm -c $(KERN_TARGETS).c -o $(KERN_TARGETS).o
	@gcc $(USER_TARGETS).c -lbpf -lelf -o $(USER_TARGETS)

clean:
	@rm -f /sys/fs/bpf/xdp_domain_map
	@rm -f /sys/fs/bpf/xdp_query_stats_map	
	@ip link set dev enp2s0 xdp off

show:
	ip link show dev $(DEV)

run:
	./dnsfw_xdp -i $(DEV)
