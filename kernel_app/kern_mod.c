#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>

#include <linux/types.h>
#include <linux/kmod.h>
#include <linux/umh.h>

#include "snap.h"

static struct kretprobe dfo_kretprobe = {
    .handler        = dfo_ret_handler,
    .entry_handler  = dfo_entry_handler,
    .kp.symbol_name = "do_filp_open",
};

static struct kretprobe fc_kretprobe = {
    .handler        = fc_ret_handler,
    .entry_handler  = fc_entry_handler,
    .kp.symbol_name = "filp_close",
};

static struct kretprobe unlink_kretprobe = {
    .handler        = unlink_ret_handler,
    .entry_handler  = unlink_entry_handler,
    .kp.symbol_name = "do_unlinkat",
};

extern struct list_head g_snap_list;
extern rwlock_t    g_snap_list_lock;

static int __init snap_init(void)
{
    int ret;
    char path[] = "/home/thesis/Desktop/work/user_app/dir_creat";
    char *argv[] = {path, "/home/dir_snap", NULL};
    char *envp[] = {NULL};

    ret = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
    printk("ret=%d\n", ret);
    if (ret){
        printk(KERN_ERR"Could not start snapshot module..will abort\n");
        return ret;
    }
    ret = plant_kretprobe(&dfo_kretprobe);
    if (ret < 0){
        return ret;
    }

    ret = plant_kretprobe(&fc_kretprobe);
    if (ret < 0){
        return ret;
    }

    ret = plant_kretprobe(&unlink_kretprobe);
    if (ret < 0){
        return ret;
    }

    ret = create_socket();
    if (ret < 0){
        return ret;
    }

    return 0;
}

static void __exit snap_uninit(void)
{
    psnapshot_entry     aux;
    struct list_head    *head;
    int count = 0;

    printk("Uninit...\n");
    read_lock(&g_snap_list_lock);
    list_for_each(head, &g_snap_list)
    {
        aux = list_entry(head, snapshot_entry, list);
        printk("file inode %lu\n", aux->inode_number);
        count += 1;
    }
    read_unlock(&g_snap_list_lock);
    printk(KERN_ERR "%d\n", count);
    //send_to_user(msg);
    remove_kretprobe(&dfo_kretprobe);
    remove_kretprobe(&fc_kretprobe);
    remove_kretprobe(&unlink_kretprobe);

    destroy_socket();
}

module_init(snap_init);
module_exit(snap_uninit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexandru-Ciprian CIHODARU <alexandru.cihodaru@gmail.com>");
MODULE_VERSION("0.1");
