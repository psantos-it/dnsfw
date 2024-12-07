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

#define MAX_QUERY_LENGTH 65

#define XDP_KERN_FILE "dnsfw_xdp.kern.o"
#define XDP_LOG_FILE "dnsfw_xdp.log"

#define DOMAIN_MAP_NAME "xdp_domains_map"
#define QUERY_MAP_NAME "xdp_query_stats"

#define DOMAIN_MAP_PIN_PATH "/sys/fs/bpf/xdp_domain_map"
#define QUERY_MAP_PIN_PATH "/sys/fs/bpf/xdp_query_stats_map"

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

static __always_inline uint32_t hash_domain(const char *domain, int len) {
	uint32_t hash = 0;
	for (int i = 0; i < len; i++) {
		hash = hash * 31 + domain[i];
	}
	return hash;
}

// Define the function to be called when ctrl-c (SIGINT) is sent to process
void signal_callback_handler(int signum) {
   printf("\nCaught signal %i\n",signum);
   // Terminate program
   exit(signum);
}

void load_blocklist(int mapfd, char *input) {

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
	

 /*   sprintf(command, "wget -q %s", input);
    system(command);
*/
    arq = fopen("blackbook.txt.2", "r");

    if (arq == NULL){
        printf("File not found\n");
        return;
    }
    while (!feof(arq)){
    line = fgets(domain, MAX_QUERY_LENGTH, arq);
    if (line){  
	  snprintf(domain_new,MAX_QUERY_LENGTH,".%s",domain); 
	  for(j = 0; j < MAX_QUERY_LENGTH; ++j)
        {
            if(domain_new[j] == '\n')
                domain3[j] = '\0';
            else domain3[j] = domain_new[j];    
        }
	  len = strlen(domain3);
	  hash_result = hash_domain(domain3,len);
	  printf("Domain [%s] [%ju]: %i\n",domain3,hash_result,i);
	  bpf_map_update_elem(mapfd, &hash_result, domain3, BPF_NOEXIST); 
	}
	  i++;
    }
    fclose(arq);
}

int main(int argc, char **argv) 
{ 
	int opt, err, i, j = 0, fd;
    int ifindex; 
    char *ifname = "lo";
	int prog_fd;
	int map_fd;
	int map_query_fd;
	char domainresult[MAX_QUERY_LENGTH];	
	static __u32 xdp_flags;
	FILE *file_log;
	__u32 value;
	__u32 key = 0;
	uint32_t next_key = 0;
	int count;
	xdp_flags = XDP_FLAGS_SKB_MODE;

	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *dns_stats = NULL;
	struct bpf_map *query = NULL;

	while((opt = getopt(argc, argv, ":i:")) != -1) 
	{ 
		switch(opt) 
		{ 
			case 'i': 
				ifname = optarg;
				if(!(ifindex = if_nametoindex(ifname)))
				{
					printf("Error: finding device %s failed\n", ifname);
				}
                else printf("interface: %i - %s\n", ifindex, ifname); 
                break; 
			case ':': 
				printf("option needs a value\n"); 
				break; 
			case '?': 
				printf("unknown option: %c\n", optopt); 
				break; 
		} 
	} 

	file_log = fopen(XDP_LOG_FILE,"w");

	// optind is for the extra arguments 
	// which are not parsed 
	for(; optind < argc; optind++){	 
		printf("extra arguments: %s\n", argv[optind]); 
	} 

  // change limits
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
	} else fprintf(file_log,"Map pinned %s\n", QUERY_MAP_PIN_PATH);

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
	

	/*	 Link XDP Prog to the interface*/
    if(bpf_program__attach_xdp(prog,ifindex)!= NULL){
        printf("Program loaded and attached to interface %s.\n", ifname);
    } else printf("Erro loading....\n");

	map_fd = bpf_object__find_map_fd_by_name(obj, DOMAIN_MAP_NAME);
	fprintf(file_log,"Map FD %i\n",map_fd);
	load_blocklist(map_fd, "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt");
	fclose(file_log);
	
	/* Setup signal handler */
	signal(SIGINT, signal_callback_handler);

    map_query_fd = bpf_object__find_map_fd_by_name(obj, QUERY_MAP_NAME);
    // Keep the program running to maintain attachment
	while (1) {
		if (i == -2){
			key = 0;
			printf("\e[1;1H\e[2J");
			printf("%-15s %-7s %-100s\n",
	       		"Key", "Count", "Domain");
		} 
		i = bpf_map_get_next_key(map_query_fd, &key, &next_key);
		//	printf("Map FD: %i-%i Key: %u Next: %u\n", map_fd, i, key, next_key);
		if(key != 0){
				bpf_map__lookup_elem(query,&key,sizeof(key), &j, sizeof(j),BPF_ANY);
				bpf_map__lookup_elem(dns_stats,&key,sizeof(key), &domainresult, sizeof(domainresult),BPF_ANY);
    			printf("[%-10u]      %-4i  %-100s\n", key, j, domainresult);
		}
			key = next_key;
		fflush(stdout);
		sleep(1);
    }
	return 0; 
} 

