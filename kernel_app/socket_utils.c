#include <linux/module.h>
#include <linux/printk.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/limits.h>

#include "snap.h"

static struct sock *nl_sk  =    NULL;
int pid;

void nl_recv_msg(struct sk_buff *skb)
{
    struct  nlmsghdr *nlh;
    int ret;
    struct inode *inode;
    struct path path;
    int size;
    char s[PATH_MAX];

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    nlh = (struct nlmsghdr*)skb->data;
    pid = nlh->nlmsg_pid;
    printk(KERN_INFO "Netlink received msg payload: %s\n",
           (char*)nlmsg_data(nlh));

    size = strlen((char *)nlmsg_data(nlh));
    strcpy(s, (char *)nlmsg_data(nlh));

    kern_path(s, LOOKUP_FOLLOW, &path);
    inode = path.dentry->d_inode;
    printk("got %s with inode %lu\n", s, inode->i_ino);

    ret = snapshot_entry_add(path, inode->i_ino);
    if (ret){
        printk(KERN_ERR "FAIL!!\n");
    }
    else {
        char path_t[] = "/bin/mkdir";
        size_t size = strlen(path.dentry->d_name.name);
        char *s = kmalloc(16+size, GFP_KERNEL);
        snprintf(s,16+size, "/home/dir_snap/%s", path.dentry->d_name.name);
        char *argv[] = {path_t, s, NULL};
        char *envp[] = {"HOME=/",
            "TERM=linux",
            "PATH=/sbin:/bin:/usr/sbin:/usr/bin" ,NULL};

        ret = call_usermodehelper(path_t, argv, envp, UMH_WAIT_PROC);
        printk("ret=%d\n", ret);
        kfree(s);
    }
}

void send_to_user(char *msg)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(msg) + 1;
    int res;

    pr_info("Creating skb.\n");
    skb = nlmsg_new(NLMSG_ALIGN(msg_size + 1), GFP_KERNEL);
    if (!skb) {
        pr_err("Allocation failure.\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size + 1, 0);
    strcpy(nlmsg_data(nlh), msg);

    pr_info("Sending skb.\n");

    res = nlmsg_unicast(nl_sk, skb, pid);
    if (res < 0)
        pr_info("nlmsg_unicast() error: %d\n", res);
    else
        pr_info("Success.\n");
}

int create_socket(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, MYPROTO, &cfg);
    if (!nl_sk) {
        pr_err("Error creating socket.\n");
        return -1;
    }

    return 0;
}

void    destroy_socket(void)
{
    netlink_kernel_release(nl_sk);
}
