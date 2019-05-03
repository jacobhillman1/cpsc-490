#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#define LOOKUP_SIZE 503 // prime number for permutation algo
#define VALUE_SIZE 23
#define MAX_BACKENDS 10

MODULE_LICENSE("Dual BSD/GPL");

// declare parameters
static char* vip = "";
module_param(vip, charp, S_IRUGO);

static char* backend_addrs[10];
static int num = 0;
module_param_array(backend_addrs, charp, &num, S_IRUGO);

// Maglev data structures
static char **connection_table;
static char **lookup_table;
static int **permutation;

// handler for incoming traffic
static struct nf_hook_ops nfho_in;

/**
 * convert string IP addr to u32
 */
unsigned int inet_addr(char *str) {
    int a,b,c,d;
    char arr[4];
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int*)arr;
} 

// taken from later version of linux
static unsigned int ip_hdrlen(const struct sk_buff *skb) {
    return ip_hdr(skb)->ihl * 4;
}

// print params (used for testing)
void print_params(void) {
    int i;
    pr_info("vip: %s", vip);

    for (i = 0; i < num; i++) {
        pr_info("%s\n", backend_addrs[i]);
    }
}

void print_permutation(void) {
    int i, j;
    for (i = 0; i < num; i++) {
        for (j = 0; j < LOOKUP_SIZE; j++){
            pr_info("[%i][%i] = %i\n", i, j, permutation[i][j]);
        }
    }
}

// return int hash between 0 and LOOKUP_SIZE
// djb2 algo taken from http://www.cse.yorku.ca/~oz/hash.html
int hash(char *str) {
    int hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    if (hash < 0) {
        hash *= -1;
    }

    return hash % LOOKUP_SIZE;
}

/**
 * populate permutation table according to Maglev spec
 */
static void pop_permutation(void) {
    int hash_val, offset, skip;
    int i, j;

    // num = number of backends
    for (i = 0; i < num; i++) {
        hash_val = hash(backend_addrs[i]);
        offset = hash_val;
        skip = (hash_val * 3) % LOOKUP_SIZE; // vary hash a little for skip

        for (j = 0; j < LOOKUP_SIZE; j++) {
            permutation[i][j] = (offset + j * skip) % LOOKUP_SIZE;
        }
    }
}

/**
 * populate the lookup table according to preferences
 * in the permutation table
 */
static int pop_lookup(void) {
    int i, n, c = 0;
    // keep track of the index for each backend in the permutation table
    int *next = (int*)kmalloc(sizeof(int) * num, GFP_ATOMIC);
    for (i = 0; i < num; i++) {
        next[i] = 0;
    }

    while (true) {
        for (i = 0; i < num; i++) {
            // find next open preference index for backend i
            c = permutation[i][next[i]];
            while (lookup_table[c] >= 0) {
                next[i] += 1;
                c = permutation[i][next[i]];
            }

            lookup_table[c] = backend_addrs[i]; // TODO: strcpy?
            next[i] += 1;
            n +=1;
            if (n == LOOKUP_SIZE) {
                return 1;
            }
        }
    }

    // shouldn't get here
    return 0;
} 

// hook for incoming packets
unsigned int fn_hook_incoming(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state) {
    struct iphdr *ip_header; // IP header struct
    struct udphdr *udp_header; // UDP header struct
    char buffer[100]; // buffer for 5-tuple
    int tuple_hash; // hash for 5-tuple

    if (!skb) {
        return NF_ACCEPT;
    }

    ip_header = (struct iphdr *)skb_network_header(skb);

    if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr *)(skb_transport_header(skb) + 
                ip_hdrlen(skb));
        if (udp_header) {
            // concat 5-tuple info into a string
            snprintf(buffer, 100, "%pI4,%d,%pI4,%d,%x",
					&ip_header->saddr,
					ntohs(udp_header->source),
					&ip_header->daddr,
					ntohs(udp_header->dest),
                    ip_header->protocol
            );

            // get hash for 5-tuple
            tuple_hash = hash(buffer);
            pr_info("hash value = %i", tuple_hash);
        }
    }
    // TEST changing the destination addr (hopefully packet will never arrive)
    // ip_header->daddr = inet_addr("172.217.164.162"); // send back to Google
    return NF_ACCEPT;
}

static int loadbalancer_init(void)
{
    int i;
    printk(KERN_ALERT "load balancer initializing.\n");

    // initialize Maglev data structures
    // TODO: does this need to be atomic? bc not interrupt handler
    connection_table = (char**)kmalloc(sizeof(char*) * LOOKUP_SIZE, GFP_ATOMIC);
    for (i = 0; i < LOOKUP_SIZE; i++) {
        connection_table[i] = (char*)kmalloc(sizeof(char) * VALUE_SIZE, GFP_ATOMIC);
    }

    lookup_table = (char**)kmalloc(sizeof(char*) * LOOKUP_SIZE, GFP_ATOMIC);
    // for (i = 0; i < LOOKUP_SIZE; i++) {
    //     lookup_table[i] = (char*)kmalloc(sizeof(char) * VALUE_SIZE, GFP_ATOMIC);
    // }

    permutation = (int**)kmalloc(sizeof(int*) * num, GFP_ATOMIC);
    for (i = 0; i < num; i++) {
        permutation[i] = (int*)kmalloc(sizeof(int) * LOOKUP_SIZE, GFP_ATOMIC);
    }

    pop_permutation();
    pop_lookup();

    // register pre-routing hook
    nfho_in.hook = fn_hook_incoming;
    nfho_in.hooknum = NF_INET_PRE_ROUTING; // edit packets first
    nfho_in.pf = PF_INET; // IPv4
    nfho_in.priority = NF_IP_PRI_FIRST;     
    nf_register_net_hook(&init_net, &nfho_in);

    return 0;
}

static void loadbalancer_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_in);
    kfree(connection_table);
    kfree(lookup_table);
    kfree(permutation);
    printk(KERN_INFO "load balancer module unloaded.\n");
}
module_init(loadbalancer_init);
module_exit(loadbalancer_exit);