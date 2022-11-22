#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int kmodule_init(void) {
        printk(KERN_INFO "Initializing this module\n");
        return 0;
}

unsigned int telnetfilter(void *priv, struct sk_buff *skb,
                        const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hrd(skb);
    tcph = (void *)iph+iph->ih1*4;

    if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)){
       printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
            ((unsigned char *)&iph->daddr)[0],
            ((unsigned char *)&iph->daddr)[1], 
            ((unsigned char *)&iph->daddr)[2], 
            ((unsigned char *)&iph->daddr)[3]);
       return NF_DROP;
      } else { return NF_ACCEPT;}
}  


int setupfilter(void) {
    print (KERN_INFO "Registering a Telnet filter.\n");
    telnetFilterHook.hook = telnetFilter;
    telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
    telnetFilterHook.pf = PF_INET;
    telnetFilterhook.priority = NF_IP_PRI_FIRST;

    // Register the hook.
    nf_register_net_hook(&init_net, &telnetFilterHook);
    return 0;
}


void removefilter(void) {
    print(KERN_INFO "Telnet filter is being removed.\n");
    nf_unregister_net_hook(&init_net, &telnetFilterHook);
}

static void kmodule_exit(void) {
        printk(KERN_INFO "Module cleanup\n");
}

module_init(kmodule_init);       
module_exit(kmodule_exit);      

MODULE_LICENSE("GPL");
