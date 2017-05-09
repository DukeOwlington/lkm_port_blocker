#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#define BLOCKED_PORT 22

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MadMax");
MODULE_DESCRIPTION("A simple Linux port blocker");
MODULE_VERSION("0.1");

/* This function to be called by hook */
static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state) {
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  struct udphdr *udp_header;
  struct tcphdr *tcp_header;

  switch (ip_header->protocol) {
    case IPPROTO_UDP:
      udp_header = (struct udphdr *)skb_transport_header(skb);
      if (udp_header->dest == htons(BLOCKED_PORT)) {
        printk(KERN_INFO "Droped udp packet.\n");
        return NF_DROP;
      }
    case IPPROTO_TCP:
      tcp_header = (struct tcphdr *)skb_transport_header(skb);
      if (tcp_header->dest == htons(BLOCKED_PORT)) {
        printk(KERN_INFO "Droped udp packet.\n");
        return NF_DROP;
      }
  }
  return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = hook_func,              /* hook function */
    .hooknum = NF_INET_PRE_ROUTING, /* watch all packets */
    .pf = PF_INET,                  /* ip protocol family */
    .priority = NF_IP_PRI_FIRST,    /* high priority */
};

static int __init init_nf(void) {
  printk(KERN_INFO "Register netfilter module.\n");
  nf_register_hook(&nfho);

  return 0;
}

static void __exit exit_nf(void) {
  printk(KERN_INFO "Unregister netfilter module.\n");
  nf_unregister_hook(&nfho);
}

module_init(init_nf);
module_exit(exit_nf);
