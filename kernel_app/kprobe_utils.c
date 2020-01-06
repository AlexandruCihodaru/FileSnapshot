#include "snap.h"
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kmod.h>
#include <linux/umh.h>
#include <linux/timekeeping.h>

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

extern rwlock_t         g_snap_list_lock;
extern struct list_head g_snap_list;

struct open_flags_c {
    int open_flag;
    umode_t mode;
    int acc_mode;
    int intent;
    int lookup_flags;
};

int     plant_kretprobe(struct kretprobe *kp)
{
    int ret;

    if (NULL != kp){
        ret = register_kretprobe(kp);
        if (ret < 0) {
            printk(KERN_ERR "Failed to register kretprobe on %s", kp->kp.symbol_name);
            return ret;
        }
    }
    return 0;
}

void    remove_kretprobe(struct kretprobe *kp)
{
    if (NULL != kp){
        unregister_kretprobe(kp);
    }
}

/////////////////////////////////////////
//  handler function tht prepare things//
//  for diff or makes checks for runc  //
/////////////////////////////////////////

int     dfo_entry_handler(struct kretprobe_instance *kp, struct pt_regs *regs)
{
    /*********************************
    ** if the file that is opened   **
    ** is proc/self/fd then I remove**
    ** the O_TRUNC flag to prevent  **
    ** emptying content of file     **
    ** and return 0 to enter in post**
    ** handler after the execution  **
    ** of probed instruction        **
    *********************************/
    struct filename *filename = (struct filename *)regs->si;
    struct open_flags_c *op = (struct open_flags_c *)regs->dx;

    if (strstr(filename->name, "/proc/self/fd")){
        op->open_flag &= ~O_TRUNC;
        return 0;
    }
    else {
        struct path path;
        int ino, ret;
        psnapshot_entry aux;

        ret = kern_path(filename->name, LOOKUP_FOLLOW, &path);
        if (!ret){
            ino = path.dentry->d_inode->i_ino;
            aux = find_snapshot_entry(ino);
            if (NULL != aux){
                if (!strstr(current->parent->comm, "kworker")){
                    size_t size = 16 + strlen(path.dentry->d_name.name) + 7;
                    char *s = (char *)kmalloc(size, GFP_KERNEL);
                    char *res, buf[256];
                    res = d_path(&path, buf, 255);
                    if (IS_ERR(res))
                    {
                        return -EPERM;
                    }

                    snprintf(s, size, "/home/dir_snap/%s/%d", path.dentry->d_name.name, current->pid);
                    //list_of_diffs_add(aux, current, s);

                    char path_t[] = "/bin/cp";
                    char *argv[] = {path_t, res, s, NULL};
                    printk("%s %ld was opened by %s %d\n", path.dentry->d_name.name, aux->inode_number,current->comm, current->pid);
                    char *envp[] = {"HOME=/",
                        "TERM=linux",
                        "PATH=/sbin:/bin:/usr/sbin:/usr/bin" ,NULL};

                    ret = call_usermodehelper(path_t, argv, envp, UMH_WAIT_PROC);
                    printk("ret=%d\n", ret);
                    if (ret){
                        printk(KERN_ERR"Could not prepare for diff..will abort\n");
                        res = NULL;
                        kfree(s);
                        return ret;
                    }
                }
                return !0;
            }
        }
    }

    /********************************
    ** return a value different of **
    ** zero to skip execution of   **
    ** post handler                **
    ********************************/
    return !0;
}

////////////////////////////////////
// hadler function for protecting //
// docker-runc against exploit    //
// CVE-2019-5736                  //
////////////////////////////////////

int     dfo_ret_handler(struct kretprobe_instance *kp, struct pt_regs *regs)
{
    /********************************
    ** this function is used for   **
    ** denying write acces for runc**
    ** file. It results in a denial**
    ** of service for docker and   **
    ** needs a reboot to work      **
    ********************************/

    struct file *retval = (struct file *)regs->ax;

    /*********************************
    ** if the file that is opened   **
    ** is docker-runc and it has    **
    ** O_WRONLY or O_RDWR flag then **
    ** we deny acces by seting the  **
    ** return value to -EACCES      **
    *********************************/

    if (likely(!IS_ERR(retval))){
        if (likely(NULL != retval->f_path.dentry->d_name.name)){
            if (unlikely(!strcmp(retval->f_path.dentry->d_name.name, "docker-runc"))){
                int flags = (u64)retval->f_flags;
                if (flags & O_WRONLY){
                    printk(KERN_ERR "Something tried to overwrtie docker-runc\n");
                    regs->ax = -EACCES;
                }
            }
        }
    }
    return 0;
}

/////////////////////////////////////////
//  handler function for notifying     //
//  usermode agent to generate diff    //
//  between in memory copy and actual  //
//  file on disk.                      //
/////////////////////////////////////////

int     fc_entry_handler(struct kretprobe_instance *kp, struct pt_regs *regs)
{
    struct file *fp = (struct file *)regs->di;
    psnapshot_entry aux;

    aux = find_snapshot_entry(fp->f_path.dentry->d_inode->i_ino);
    if (NULL != aux){
        int res;
        res = is_closed_by_opener(current, aux);
        if (res){
            printk("file %s %ld was closed by %s %d\n", fp->f_path.dentry->d_name.name, fp->f_inode->i_ino, current->comm, current->pid);
            //call_usermodehelper for diff
        }
    }
    return !0;
}

int     fc_ret_handler(struct kretprobe_instance *kp, struct pt_regs *regs)
{
    return 0;
}


/////////////////////////////
// after a file is deleted //
// we remove that entry    //
// from out watch list     //
/////////////////////////////

static int remove_from_watchlist(struct filename *fn)
{
    struct path path;
    int ino, ret;
    psnapshot_entry aux, var;

    ret = kern_path(fn->name, LOOKUP_FOLLOW, &path);
    if (!ret){
        ino = path.dentry->d_inode->i_ino;
        aux = find_snapshot_entry(ino);
        if (NULL != aux){
            struct list_head *head;

            write_lock(&g_snap_list_lock);
            list_for_each(head, &g_snap_list){
                var = list_entry(head, snapshot_entry, list);
                if (aux == var){
                    list_del(head);
                    write_unlock(&g_snap_list_lock);
                    return 0;
                }
            }
            write_unlock(&g_snap_list_lock);
        }
    }
    return -1;
}

/////////////////////////////////////////
//  handler function for file deletion //
//  it call an usermode helper that    //
//  copy the deleted file to a snap    //
//  location                           //
/////////////////////////////////////////

int     unlink_entry_handler(struct kretprobe_instance *kp, struct pt_regs *regs)
{
    struct filename *fn = (struct filename *)regs->si;
    struct path path;
    int ino, ret;
    psnapshot_entry aux;

    ret = kern_path(fn->name, LOOKUP_FOLLOW, &path);
    if (!ret){
        ino = path.dentry->d_inode->i_ino;
        aux = find_snapshot_entry(ino);
        if (NULL != aux){
            /****************************
            * if the file to be deleted**
            * is in out watch list then**
            * we copy it to the snap   **
            * location in a file which **
            * has name the time of del **
            ****************************/

            char *res, buf[256];
            res = d_path(&path, buf, 255);
            if (IS_ERR(res))
            {
                return -EPERM;
            }

            char path_t[] = "/bin/cp";
            char tod[40];
            struct timespec ts;
            struct tm tm;

            getnstimeofday(&ts);
            time_to_tm(ts.tv_sec, sys_tz.tz_minuteswest, &tm);
            snprintf(tod,35, "/home/dir_snap/%.2d_%.2d_%.4ld_%.2d_%.2d_%.2d", tm.tm_mday, tm.tm_mon+1,tm.tm_year+1900, tm.tm_hour, tm.tm_min, tm.tm_sec);

            char *argv[] = {path_t, res, tod, NULL};
            char *envp[] = {"HOME=/",
                "TERM=linux",
                "PATH=/sbin:/bin:/usr/sbin:/usr/bin" ,NULL};

            ret = call_usermodehelper(path_t, argv, envp, UMH_WAIT_PROC);
            printk("ret=%d\n", ret);
            if (ret){
                printk(KERN_ERR"Could not create new snapshot entry..will abort\n");
                return ret;
            }

            printk("delete %ld \n", aux->inode_number);
            res = NULL;
            ret = remove_from_watchlist(fn);
            return !0;
        }
    }

    return !0;
}


int     unlink_ret_handler(struct kretprobe_instance *kp, struct pt_regs *regs)
{
    //will do something with the restore here
    return 0;
}
