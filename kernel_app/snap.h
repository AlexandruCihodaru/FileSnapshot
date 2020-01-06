#ifndef _SNAP_H_
#define _SNAP_H

#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/skbuff.h>

#define MYPROTO NETLINK_USERSOCK
#define MYGRP 1

typedef struct _list_of_diffs
{
    struct task_struct *ts;
    char *file_for_diff;
    struct list_head list;
} list_of_diffs, *plist_of_diffs;

typedef struct _snapshot_entry
{
    struct path         file_path;
    unsigned long       inode_number;
    list_of_diffs       lod;
    rwlock_t            snap_lock;
    struct list_head    list;

} snapshot_entry, *psnapshot_entry;

/*kprobes*/
int     plant_kretprobe(struct kretprobe    *kp);
void    remove_kretprobe(struct kretprobe   *kp);

int     dfo_entry_handler(struct kretprobe_instance *kp, struct pt_regs *regs);
int     dfo_ret_handler(struct kretprobe_instance   *kp, struct pt_regs *regs);

int     unlink_entry_handler(struct kretprobe_instance *kp, struct pt_regs *regs);
int     unlink_ret_handler(struct kretprobe_instance   *kp, struct pt_regs *regs);

int     fc_entry_handler(struct kretprobe_instance *kp, struct pt_regs *regs);
int     fc_ret_handler(struct kretprobe_instance   *kp, struct pt_regs *regs);
/*sockets*/
int     create_socket(void);

void    nl_recv_msg(struct sk_buff  *skb);
void    send_to_user(char   *msg);

void    destroy_socket(void);

/*engine*/
int             snapshot_entry_add(struct path, unsigned long);
psnapshot_entry find_snapshot_entry(unsigned long);
int             is_closed_by_opener(struct task_struct *, psnapshot_entry );
void            list_of_diffs_add(psnapshot_entry , struct task_struct *, char *);
#endif
