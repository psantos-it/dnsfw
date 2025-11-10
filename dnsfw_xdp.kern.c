/* Copyright (c) 2024 Pedro Santos */

/**************************************************************** 
 * 
 * dnsfw_xdp.kern.c:
 * programa funcional usando apenas o dominio
 * 	   
****************************************************************/
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT 53
#define DNS_QUERY_REQUEST 0
#define MAX_QUERY_LENGTH 251
#define MAX_MAP_ENTRIES 20480
#define MAX_STATS_ENTRIES 50

struct domain {
	uint16_t qtype;
	uint16_t qclass;
	uint16_t qlength;
	char qname[MAX_QUERY_LENGTH];
//	char dname[MAX_QUERY_LENGTH];		
} domain;

struct dns_hdr{
	uint16_t id;

	uint8_t rd	:1;//recursion desired
	uint8_t tc	:1;//truncated message
	uint8_t aa	:1;//authoritive answer
	uint8_t opcode	:4;//purpose of message
	uint8_t qr	:1;//query/response flag

	uint8_t rcode	:4;//response code
	uint8_t cd	:1;//checking desiabled
	uint8_t ad	:1;//authenticated data
	uint8_t z	:1;// reserved
	uint8_t ra	:1;//recursion available

	uint16_t qdcount;//number of question entries
	uint16_t ancount;//number of answer entries
	uint16_t nscount;//number of authority entries
	uint16_t arcount;//number of resource entries
} dns_hdr;

// Functions
static int parse_query (struct xdp_md *ctx, void *query_start, struct domain *q);
//static int parse_host_domain(struct domain *q, const int ql);
static __always_inline uint32_t hash_domain(const char *domain, int len);
uint64_t hash_fnv1a(const char *domain, int len);
uint64_t hash_murmur(const char *domain, int len);

// Maps
struct bpf_map_def {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint64_t);
	__type(value, char[MAX_QUERY_LENGTH]);
	__uint(max_entries, MAX_MAP_ENTRIES);
} xdp_domains_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint64_t); 
	__type(value, int); 
	__uint(max_entries, MAX_STATS_ENTRIES);
} xdp_query_stats SEC(".maps");

SEC("dnsfw_xdp")
int dns(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth_header = data;
    struct iphdr *ip_header = NULL; 
	struct udphdr *udp_header = NULL; 
	struct dns_hdr *dns_header = NULL;
	struct domain q;

    uint32_t eth_header_size = 0;
    uint32_t ip_header_size = 0;
    uint32_t udp_header_size = 0;
    uint32_t dns_header_size = 0;
    uint32_t saddr = 0;
    uint32_t daddr = 0;
	uint64_t hash_r;
	uint32_t *r;
	char *result = NULL;
	int q_length;
	int d_length;
	

    /* validate ETH header size*/
    eth_header_size = sizeof(*eth_header);
    if ((void *)(eth_header + 1) > data_end)
        return XDP_PASS;

    /* validate IP header size*/
	ip_header = (void *)eth_header + eth_header_size;
	ip_header_size = sizeof(*ip_header);
	if((void *)ip_header + ip_header_size > data_end)
	{
		return XDP_PASS;
	}
	/* Validate UDP protocol (DNS request)*/
	if(ip_header->protocol != IPPROTO_UDP)
	{
		return XDP_PASS;
	}
	
	/* Validate UDP header size*/
	udp_header = (void *)ip_header + ip_header_size;
	udp_header_size = sizeof(*udp_header);
	if((void *)udp_header + udp_header_size > data_end)
	{
		return XDP_PASS;
	}

   	/* Validate DNS port */
	if(bpf_htons(udp_header->dest) != DNS_PORT)
	{
		return XDP_PASS;
	}
		saddr = ip_header->saddr;
        daddr = ip_header->daddr;
		__u32 key = 0;

		/* Validate DNS header size */ 
		dns_header = (void *)udp_header + udp_header_size;
		dns_header_size = sizeof(*dns_header);
    	if((void *)dns_header + dns_header_size > data_end)
		{
			return XDP_PASS;
		}
	/* Analyze DNS query */
	if(dns_header->qr == DNS_QUERY_REQUEST)
	{
        
        void *query_start = (void *)dns_header + dns_header_size;
		uint32_t counter = 0;

        /* Extract domain from DNS query */
		q_length = parse_query(ctx, query_start, &q);

//		bpf_printk("Query: [%s]\n", q.qname);
//		bpf_printk("Domain>: [%s]\n", q.dname);
        
		if(q_length != -1){
			//hash_r = hash_domain(q.qname,q_length);
			hash_r = hash_fnv1a(q.qname,q_length);
		//	bpf_printk("Hash: [%u]\n", hash_r);
			result = bpf_map_lookup_elem(&xdp_domains_map,&hash_r);
			if(result){
				bpf_printk("domain blocked [%s]\n", result);
				r = bpf_map_lookup_elem(&xdp_query_stats, &hash_r);
				if(r){
					counter = *r;
					counter += 1;
					bpf_map_update_elem(&xdp_query_stats, &hash_r, &counter, BPF_ANY);
				} else{
					counter += 1;
					bpf_map_update_elem(&xdp_query_stats, &hash_r, &counter, BPF_ANY);
		//			bpf_printk("stats [%u]\n", r);
				}
				return XDP_DROP;
				//return XDP_PASS; //pass for debug
			} //else bpf_printk("domain allowed [%s]\n", q.qname);
		} 
    }
    
    return XDP_PASS;
}
/**************************************** hash_domain ******************************************************/
static __always_inline uint32_t hash_domain(const char *domain, int len) {
	uint32_t hash = 5381; //5381
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

/**************************************** parse_query ******************************************************/
static int parse_query(struct xdp_md *ctx, void *query_start, struct domain *q){
	void *data_end = (void *)(long)ctx->data_end;
	void *cursor = query_start;
	uint16_t pos = 0, i=0;

	q->qname[0] = '\0';
	q->qclass = 0;
	q->qtype = 0;
	
	for(i=0; i<MAX_QUERY_LENGTH; ++i){
		
		if(cursor + 1 > data_end)
			break;
		if(*(char *)(cursor) == 0){
			if(cursor + 5 > data_end)
				break;
			else{
				q->qtype = bpf_htons(*(uint16_t *)(cursor+1));
				q->qclass = bpf_htons(*(uint16_t *)(cursor+3));
				q->qlength = pos;
			}
			q->qname[pos] = *(char *)(cursor);
			q->qname[pos]='\0';
			return pos;
		}
		if (*(char *)(cursor) < 32 ){
			q->qname[pos] = '.';
		} else{
			
			q->qname[pos] = *(char *)(cursor);
		}
		++pos;
		++cursor;
	}
	q->qname[pos-1]='\0';
	return -1;
}

/**************************************** parse_host_domain ******************************************************/
// static int parse_host_domain(struct domain *q, const int ql)
// {
// 	char *s = q->qname;
// 	int hl=0, dl;
	
// 	++s;
// 	for (; *s != '.'; ++s){
// 		if (*s == '\0')
// 			return -1;
// 		++hl;
// 	}
// 	dl = ql-hl-1;
// 	if (hl < ql){
// 		bpf_probe_read_kernel_str(q->dname, ql-hl, s);
// 		q->dname[dl]= 0;
// 	}


// 	return dl;

// }

char _license[] SEC("license") = "GPL";