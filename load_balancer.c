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

MODULE_LICENSE("Dual BSD/GPL");

// declare parameters
static char* vip = "";
module_param(vip, charp, S_IRUGO);

static char* backend_addrs[10];
static int num = 0;
module_param_array(backend_addrs, charp, &num, S_IRUGO);

// handler for incoming traffic
static struct nf_hook_ops nfho_in;

struct backend_addr {
    __u32 addr;
    __u16 port;
};

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

// hook for incoming packets
unsigned int fn_hook_incoming(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state) {
    struct iphdr *ip_header; // IP header struct
    struct udphdr *udp_header; // UDP header struct

    if (!skb) {
        return NF_ACCEPT;
    }

    ip_header = (struct iphdr *)skb_network_header(skb);
    // printk(KERN_ALERT "ip_header saddr = %pI4", &ip_header->saddr);

    if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr *)(skb_transport_header(skb) + 
                ip_hdrlen(skb));
        if (udp_header) {
            // concat 5-tuple info into a string
            pr_info("SRC: (%pI4):%d --> DST: (%pI4):%d, protocol = %x\n",
					&ip_header->saddr,
					ntohs(udp_header->source),
					&ip_header->daddr,
					ntohs(udp_header->dest),
                    ip_header->protocol
            );
        }
    }
    // TEST changing the destination addr (hopefully packet will never arrive)
    ip_header->daddr = inet_addr("172.217.164.162"); // send back to Google
    return NF_ACCEPT;
}

static int loadbalancer_init(void)
{
    // char *test = "";
    printk(KERN_ALERT "load balancer initializing.\n");

    // register pre-routing hook
    nfho_in.hook = fn_hook_incoming;
    nfho_in.hooknum = NF_INET_PRE_ROUTING;  // edit packets first
    nfho_in.pf = PF_INET;                   // IPv4
    nfho_in.priority = NF_IP_PRI_FIRST;     
    nf_register_net_hook(&init_net, &nfho_in);

    // snprintf(test, 32, "%i", 10);
    // pr_info("snprintf output = %s", test);


    return 0;
}

static void loadbalancer_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_in);
    printk(KERN_INFO "load balancer module unloaded.\n");
}
module_init(loadbalancer_init);
module_exit(loadbalancer_exit);