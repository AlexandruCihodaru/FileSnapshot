#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include "snap.h"

struct list_head     g_snap_list = LIST_HEAD_INIT(g_snap_list);
rwlock_t    g_snap_list_lock = __RW_LOCK_UNLOCKED(g_snap_list_lock);


/////////////////////////////////////
//    on each entry on a hooked    //
//    function this function is    //
//    called to check if the       //
//    accessed file is on snapshot //
//    watch list                   //
/////////////////////////////////////

psnapshot_entry find_snapshot_entry(unsigned long inr)
{
    psnapshot_entry     aux;
    struct list_head    *head;

    read_lock(&g_snap_list_lock);
    list_for_each(head, &g_snap_list)
    {
        aux = list_entry(head, snapshot_entry, list);
        if (aux->inode_number == inr){
            read_unlock(&g_snap_list_lock);
            return aux;
        }
    }
    read_unlock(&g_snap_list_lock);
    return NULL;
}

int is_closed_by_opener(struct task_struct *ts, psnapshot_entry ps)
{
    plist_of_diffs pod;
    struct list_head *head;

    read_lock(&ps->snap_lock);
    list_for_each(head, &ps->lod.list)
    {
        pod = list_entry(head, list_of_diffs, list);
        if (!memcmp(pod->ts, ts, sizeof(struct task_struct))){
            read_unlock(&ps->snap_lock);
            return 1;
        }
    }
    read_unlock(&ps->snap_lock);
    return 0;
}


/////////////////////////////////////
//    this is used to add a new    //
//    file to the watch list       //
/////////////////////////////////////
int     snapshot_entry_add(struct path path_to_file, unsigned long inr)
{
    psnapshot_entry   file_to_add = NULL;
    file_to_add = find_snapshot_entry(inr);
    if (NULL == file_to_add){
        file_to_add = (psnapshot_entry)kmalloc(sizeof(snapshot_entry), GFP_ATOMIC);
        if (!file_to_add){
            printk(KERN_ERR "Failed to allocate memory\n");
            return -1;
        }
        else{
            file_to_add->file_path = path_to_file;
            file_to_add->inode_number = inr;
            file_to_add->snap_lock = __RW_LOCK_UNLOCKED(file_to_add->snap_lock);
            INIT_LIST_HEAD(&file_to_add->lod.list);
            write_lock(&g_snap_list_lock);
            list_add_tail(&(file_to_add->list), &g_snap_list);
            write_unlock(&g_snap_list_lock);
        }
    }
    else{
        printk(KERN_INFO "File is already in watch list\n");
        return -2;
    }
    return 0;
}

void     list_of_diffs_add(psnapshot_entry snap, struct task_struct *ts, char *filename)
{
    list_of_diffs lod;

    lod.ts = ts;
    lod.file_for_diff = filename;
    write_lock(&snap->snap_lock);
    list_add_tail(&(lod.list), &snap->lod.list);
    write_unlock(&snap->snap_lock);
}
