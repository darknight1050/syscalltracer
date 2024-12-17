#include <linux/kernel.h> 
#include "config.h"

noinline void hook_do_syscall_64 HOOK_PARAMS;

bool install_hook(void);
bool uninstall_hook(void);