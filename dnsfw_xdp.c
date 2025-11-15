#include <stdio.h> 
#include <stdlib.h>
#include <errno.h> 
#include <unistd.h> //sleep
#include <sys/resource.h> //memory limits
#include <net/if.h> // if_nametoindex 
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <string.h>
#include <signal.h>
#include <bits/getopt_core.h>

#define MAX_QUERY_LENGTH 56 //251

// XDP Flags - definições corretas (forçadas)
#undef XDP_FLAGS_SKB_MODE
#undef XDP_FLAGS_DRV_MODE
#undef XDP_FLAGS_HW_MODE
#undef XDP_FLAGS_REPLACE
#undef XDP_FLAGS_UPDATE_IF_NOEXIST

#define XDP_FLAGS_UPDATE_IF_NOEXIST	0
#define XDP_FLAGS_SKB_MODE		(1U << 0)
#define XDP_FLAGS_DRV_MODE		(1U << 1)
#define XDP_FLAGS_HW_MODE		(1U << 2)
#define XDP_FLAGS_REPLACE		(1U << 3)

#define XDP_KERN_FILE "dnsfw_xdp.kern.o"
#define XDP_LOG_FILE "dnsfw_xdp.log"

#define DOMAIN_MAP_NAME "xdp_domains_map"
#define QUERY_MAP_NAME "xdp_query_stats"

#define DOMAIN_MAP_PIN_PATH "/sys/fs/bpf/xdp_domain_map"
#define QUERY_MAP_PIN_PATH "/sys/fs/bpf/xdp_query_stats_map"

// Modos XDP disponíveis
#define XDP_MODE_NATIVE  0  // xdpdrv (driver native)
#define XDP_MODE_OFFLOAD 1  // xdpoffload (hardware offload)
#define XDP_MODE_SKB     2  // xdpsock (fallback generic)

static void list_avail_progs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	printf("BPF object (%s) listing available XDP functions\n",
	       bpf_object__name(obj));

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__type(pos) == BPF_PROG_TYPE_XDP)
			printf(" %s\n", bpf_program__name(pos));
	}
}

/**************************************** hash_domain ******************************************************/
static __always_inline uint32_t hash_domain(const char *domain, int len) {
	uint64_t hash = 5381;
	for (int i = 0; i < len; i++) {
		hash = hash * 33 + domain[i];
	}
	return hash;
}

uint64_t hash_fnv1a(const char *domain, int len) {
	uint64_t hash = 0xcbf29ce484222325ULL;
	for (int i = 0; i < len; i++) {
		hash ^= (unsigned char)domain[i];
		hash *= 0x100000001b3ULL;
	}
	return hash;
}

uint64_t hash_murmur(const char *domain, int len) {
	uint64_t h1 = 0;
	const uint64_t c1 = 0x87c4b0fd;
	const uint64_t c2 = 0x4cf5ad43;
	
	for (int i = 0; i < len; i++) {
		uint64_t k1 = domain[i];
		k1 *= c1;
		k1 = (k1 << 31) | (k1 >> 33);
		k1 *= c2;
		h1 ^= k1;
		h1 = (h1 << 27) | (h1 >> 37);
		h1 = h1 * 5 + 0x52dce729;
	}
	return h1;
}

void signal_callback_handler(int signum) {
   printf("\nCaught signal %i\n",signum);
   exit(signum);
}

void load_blocklist(int mapfd, const char *filename) {

    char command[2048];
    char domain[MAX_QUERY_LENGTH];
	char domain3[MAX_QUERY_LENGTH];
	char domain_new[MAX_QUERY_LENGTH];
    int i = 0;
	int j;
	int len;
    FILE* arq;
    char *line;
	uint64_t hash_result = 0;
	
    arq = fopen(filename, "r");

    if (arq == NULL){
        printf("File not found\n");
        return;
    }
    while (!feof(arq)){
    line = fgets(domain, MAX_QUERY_LENGTH, arq);
    if (line){  
	  snprintf(domain_new, sizeof(domain_new), ".%.*s", (int)sizeof(domain_new) - 2, domain);
	  for(j = 0; j < MAX_QUERY_LENGTH; ++j)
        {
            if(domain_new[j] == '\n')
                domain3[j] = '\0';
            else domain3[j] = domain_new[j];    
        }
	  len = strlen(domain3);
	  hash_result = hash_fnv1a(domain3,len);
	  //printf("Domain [%s] [%ju]: %i\n",domain3,hash_result,i);
	  bpf_map_update_elem(mapfd, &hash_result, domain3, BPF_NOEXIST); 
	}
	  i++;
    }
    fclose(arq);
}

// Função auxiliar para converter string do modo XDP
static int parse_xdp_mode(const char *mode_str) {
	if (strcmp(mode_str, "native") == 0 || strcmp(mode_str, "xdpdrv") == 0) {
		return XDP_MODE_NATIVE;
	} else if (strcmp(mode_str, "offload") == 0 || strcmp(mode_str, "xdpoffload") == 0) {
		return XDP_MODE_OFFLOAD;
	} else if (strcmp(mode_str, "skb") == 0 || strcmp(mode_str, "xdpsock") == 0) {
		return XDP_MODE_SKB;
	}
	return -1;  // Modo inválido
}

// Função auxiliar para converter modo para string
static const char* xdp_mode_to_string(int mode) {
	switch(mode) {
		case XDP_MODE_NATIVE:
			return "native (xdpdrv)";
		case XDP_MODE_OFFLOAD:
			return "offload (xdpoffload)";
		case XDP_MODE_SKB:
			return "skb (xdpsock)";
		default:
			return "unknown";
	}
}

// Função para fazer attach do programa XDP com o modo especificado
// Retorna: 0 se sucesso, erro code se falha
static int attach_xdp_program(struct bpf_program *prog, int ifindex, int xdp_mode) {
	struct bpf_xdp_attach_opts opts = {
		.sz = sizeof(opts),
	};
	__u32 flags = 0;
	int prog_fd;
	int err;
	
	printf("Attempting to attach XDP program in %s mode...\n", xdp_mode_to_string(xdp_mode));
	
	// Selecionar flag correta baseada no modo
	switch(xdp_mode) {
		case XDP_MODE_NATIVE:
			flags = XDP_FLAGS_DRV_MODE;
			printf("  Mode: XDP_FLAGS_DRV_MODE (native driver)\n");
			break;
		case XDP_MODE_OFFLOAD:
			flags = XDP_FLAGS_HW_MODE;
			printf("  Mode: XDP_FLAGS_HW_MODE (hardware offload)\n");
			break;
		case XDP_MODE_SKB:
			flags = XDP_FLAGS_SKB_MODE;
			printf("  Mode: XDP_FLAGS_SKB_MODE (kernel generic)\n");
			printf("  Note: SKB mode runs in kernel space (slower)\n");
			break;
		default:
			printf("Error: Invalid XDP mode\n");
			return -EINVAL;
	}
	
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		printf("Error: Failed to get program FD: %d\n", prog_fd);
		return prog_fd;
	}
	
	// Usar bpf_xdp_attach com as flags corretas e struct bpf_xdp_attach_opts
	printf("  Using bpf_xdp_attach with flags=0x%x\n", flags);
	err = bpf_xdp_attach(ifindex, prog_fd, flags, &opts);
	
	if (err == 0) {
		printf("  Attachment successful (flags=0x%x)\n", flags);
		return 0;  // Sucesso!
	}
	
	printf("  bpf_xdp_attach failed: %d (%s)\n", err, strerror(-err));
	
	// Fallback: tentar com bpf_program__attach_xdp (modo nativo apenas)
	if (xdp_mode == XDP_MODE_NATIVE) {
		printf("  Falling back to bpf_program__attach_xdp...\n");
		struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
		
		if (link && !libbpf_get_error(link)) {
			printf("  Fallback attachment successful\n");
			return 0;  // Sucesso!
		}
		
		if (link) {
			err = (int)libbpf_get_error(link);
			printf("  Fallback failed: %d\n", err);
			return err;
		}
	}
	
	return err;
}

int main(int argc, char **argv) 
{ 
	int opt, err, i, j = 0, fd;
	static bool verbose = false;
    int ifindex; 
    char *ifname = "lo";
	char *domain_filename = "blackbook.txt";
	int prog_fd;
	int map_fd;
	int map_query_fd;
	char domainresult[MAX_QUERY_LENGTH];	
	FILE *file_log;
	__u64 key = 0;
	uint32_t next_key = 0;
	int count;
	int xdp_mode = XDP_MODE_NATIVE;  // Modo padrão: xdpdrv
	char *mode_str = "native";
	int attach_result;  // Resultado do attach

	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *dns_stats = NULL;
	struct bpf_map *query = NULL;

	// Parse de argumentos com nova opção -m para modo XDP
	while((opt = getopt(argc, argv, "f:i:m:vh")) != -1) 
	{ 
		switch(opt) 
		{
			case 'f':
            	domain_filename = optarg;
            	break;
    	    case 'i':
				ifname = optarg;
				if(!(ifindex = if_nametoindex(ifname)))
				{
					printf("Error: finding device %s failed\n", ifname);
				}
                else printf("interface: %i - %s\n", ifindex, ifname); 
                break;
			case 'm':
				mode_str = optarg;
				xdp_mode = parse_xdp_mode(mode_str);
				if (xdp_mode < 0) {
					printf("Error: Invalid XDP mode '%s'\n", mode_str);
					printf("Valid modes: native (xdpdrv), offload (xdpoffload), skb (xdpsock)\n");
					return 1;
				}
				printf("XDP mode selected: %s\n", xdp_mode_to_string(xdp_mode));
				break;
			case 'v':
            	verbose = true;
            	break;
	 	    case 'h':
        	default:
            	printf("Usage: %s [-f domain_list] [-i interface] [-m xdp_mode] [-v] [-h]\n", argv[0]);
            	printf("  -f ARQUIVO   : Arquivo com a lista de dominios\n");
            	printf("  -i INTERFACE : Interface para anexar o programa\n");
				printf("  -m MODE      : Modo XDP (native, offload, skb) [default: native]\n");
				printf("               : native   = xdpdrv (driver native)\n");
				printf("               : offload  = xdpoffload (hardware offload via SmartNIC/DPU)\n");
				printf("               : skb      = xdpsock (fallback, generic)\n");
				printf("  -v           : Modo verbose (estatisticas)\n");
				printf("  -h           : Exibir esta ajuda\n");
				printf("\nExamples:\n");
				printf("  %s -i eth0 -m native       # Attach em modo driver nativo\n", argv[0]);
				printf("  %s -i eth0 -m offload      # Attach em modo hardware offload\n", argv[0]);
            	return opt == 'h' ? 0 : 1;
		} 
	} 

	file_log = fopen(XDP_LOG_FILE,"w");

	for(; optind < argc; optind++){	 
		printf("extra arguments: %s\n", argv[optind]); 
	} 

  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
    return 1;
  }

	/* Verify XDP object file existence */
	if(!(obj = bpf_object__open_file(XDP_KERN_FILE, NULL)) || libbpf_get_error(obj))
	{
		printf("Error: opening BPF object file failed\n");
		return -1;
	} else printf("BPF object file opened\n");

      /* List available programs */
	list_avail_progs(obj);

	/* Find Map - DNS STATS */
	if(!(dns_stats = bpf_object__find_map_by_name(obj, DOMAIN_MAP_NAME)))
	{
		fprintf(file_log,"Error: Map " DOMAIN_MAP_NAME " not found\n");
		return -1;
	} else fprintf(file_log,"Map founded %s\n",DOMAIN_MAP_NAME);

	/* Pin Map */
	if(bpf_map__set_pin_path(dns_stats, DOMAIN_MAP_PIN_PATH))
	{
		fprintf(file_log,"Error: pinning " DOMAIN_MAP_PIN_PATH " to \"%s\" failed\n", DOMAIN_MAP_PIN_PATH);
		return -1;
	} else fprintf(file_log,"Map pinned %s\n", DOMAIN_MAP_NAME);

	/* Find Query Map */
	if(!(query = bpf_object__find_map_by_name(obj, QUERY_MAP_NAME)))
	{
		fprintf(file_log,"Error: Map " QUERY_MAP_NAME " not found\n");
		return -1;
	} else fprintf(file_log,"Map founded %s\n",QUERY_MAP_NAME);

	/* Pin Map */
	if(bpf_map__set_pin_path(query, QUERY_MAP_PIN_PATH))
	{
		fprintf(file_log,"Error: pinning " QUERY_MAP_PIN_PATH " to \"%s\" failed\n", QUERY_MAP_PIN_PATH);
		return -1;
	} else fprintf(file_log,"Map pinned %s\n", QUERY_MAP_NAME);

	/* Load XDP object file */
	prog = bpf_object__find_program_by_name(obj,"dns");
	err = bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
	err = bpf_program__set_expected_attach_type(prog,BPF_XDP);
	if(bpf_object__load(obj))
	{
		printf("Error: loading BPF obj file failed!\n");
		bpf_object__close(obj);
		return -1;
	} else printf("BPF obj file loaded\n");
	

	/*	 Link XDP Prog to the interface with specified mode */
    attach_result = attach_xdp_program(prog, ifindex, xdp_mode);
    
    if(attach_result == 0){
        printf("Program loaded and attached to interface %s in %s mode.\n", ifname, xdp_mode_to_string(xdp_mode));
        fprintf(file_log, "XDP Program attached in %s mode\n", xdp_mode_to_string(xdp_mode));
    } else {
        printf("Error loading/attaching XDP program in %s mode (err=%d)\n", xdp_mode_to_string(xdp_mode), attach_result);
        fprintf(file_log, "Error: Failed to attach XDP program in %s mode (err=%d)\n", xdp_mode_to_string(xdp_mode), attach_result);
        bpf_object__close(obj);
        fclose(file_log);
        return -1;
    }

	map_fd = bpf_object__find_map_fd_by_name(obj, DOMAIN_MAP_NAME);
	fprintf(file_log,"Map FD %i\n",map_fd);
	load_blocklist(map_fd,domain_filename);
	
	/* Setup signal handler */
	signal(SIGINT, signal_callback_handler);
	signal(SIGTERM, signal_callback_handler);

    map_query_fd = bpf_object__find_map_fd_by_name(obj, QUERY_MAP_NAME);
    
    // Keep the program running to maintain attachment
	while (1) {
		if (verbose){
			if (i == -2){
				key = 0;
				printf("\e[1;1H\e[2J");
				printf("%-15s %-7s %-100s\n",
	       			"Key", "Count", "Domain");
			} 
			i = bpf_map_get_next_key(map_query_fd, &key, &next_key);
			if(key != 0){
					bpf_map__lookup_elem(query,&key,sizeof(key), &j, sizeof(j),BPF_ANY);
					bpf_map__lookup_elem(dns_stats,&key,sizeof(key), &domainresult, sizeof(domainresult),BPF_ANY);
    				printf("[%-10llu]      %-4i  %-100s\n", key, j, domainresult);
			}
			key = next_key;
			fflush(stdout);
			sleep(1);
		}
    }
    
    fclose(file_log);
	return 0; 
}