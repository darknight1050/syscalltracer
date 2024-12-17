#include "syscallhook.h"
#include "utils.h"
#include "config.h"
#include <linux/module.h> 

#ifdef USE_VMALLOC
static void* vmalloc_exec(unsigned long size, const void* caller)
{
    void*(*__vmalloc_node_range)(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller);
    __vmalloc_node_range = _kallsyms_lookup_name("__vmalloc_node_range");
    return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END, GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE, caller);
}
#else
static void exec_memory_func(void) 
{ 
    asm volatile("\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        nop\n\t\
        ");
}
#endif

static void* exec_memory;
static void* orig_do_syscall_64;
static void* do_syscall_64;

bool install_hook(void) {
    pr_info("Hooking...\n"); 
    do_syscall_64 = _kallsyms_lookup_name("do_syscall_64");
    pr_info("do_syscall_64 %px\n", do_syscall_64);

    const char save_registers[] = { 
        0x9C, //pushf
        0x50, //push rax
        0x53, //push rbx
        0x51, //push rcx
        0x52, //push rdx
        0x55, //push rbp
        0x56, //push rsi
        0x57, //push rdi
        0x41, 0x50, //push r8
        0x41, 0x51, //push r9
        0x41, 0x52, //push r10
        0x41, 0x53, //push r11
        0x41, 0x54, //push r12
        0x41, 0x55, //push r13
        0x41, 0x56, //push r14
        0x41, 0x57, //push r15
    };

    const char restore_registers[] = { 
        0x41, 0x5F, //pop r15
        0x41, 0x5E, //pop r14
        0x41, 0x5D, //pop r13
        0x41, 0x5C, //pop r12
        0x41, 0x5B, //pop r11
        0x41, 0x5A, //pop r10
        0x41, 0x59, //pop r9
        0x41, 0x58, //pop r8
        0x5F, //pop rdi
        0x5E, //pop rsi
        0x5D, //pop rbp
        0x5A, //pop rdx
        0x59, //pop rcx
        0x5B, //pop rbx
        0x58, //pop rax
        0x9D, //popf
    };
    
    const char absJumpInstructions[] = { 
        0x49, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //movabs r10,0xaaaaaaaaaaaaaaaa
		0x41, 0xFF, 0xE2, //jmp r10
    };

    const char absCallInstructions[] = { 
        0x49, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //movabs r10,0xaaaaaaaaaaaaaaaa
		0x41, 0xFF, 0xD2, //call r10
    };

    disable_write_protection();
    #ifdef USE_VMALLOC
    size_t exec_size = sizeof(save_registers) + sizeof(absCallInstructions) + sizeof(restore_registers) + INST_ALIGNED;
    exec_memory = vmalloc_exec(exec_size, do_syscall_64);
    #else
    exec_memory = (void*)exec_memory_func;
    #endif
    pr_info("exec_memory %px\n", exec_memory);
    if(exec_memory) {
        memcpy(exec_memory, (void*)save_registers, sizeof(save_registers));
        
        *(void**)(absCallInstructions + 2) = (void*)hook_do_syscall_64;
        memcpy(exec_memory + sizeof(save_registers), (void*)absCallInstructions, sizeof(absCallInstructions));

        memcpy(exec_memory + sizeof(save_registers) + sizeof(absCallInstructions), (void*)restore_registers, sizeof(restore_registers));

        orig_do_syscall_64 = exec_memory + sizeof(save_registers) + sizeof(absCallInstructions) + sizeof(restore_registers);
        pr_info("orig_do_syscall_64 %px\n", (void*)orig_do_syscall_64); 
        memcpy(orig_do_syscall_64, do_syscall_64, INST_ALIGNED);
        
        *(void**)(absJumpInstructions + 2) = do_syscall_64 + INST_ALIGNED;
        memcpy(orig_do_syscall_64 + INST_ALIGNED, (void*)absJumpInstructions, sizeof(absJumpInstructions));

        DUMP_MEMORY(exec_memory, DUMP_SIZE);

        *(void**)(absJumpInstructions + 2) = exec_memory;
        memcpy(do_syscall_64, (void*)absJumpInstructions, sizeof(absJumpInstructions));
        DUMP_MEMORY(do_syscall_64, DUMP_SIZE);

        pr_info("Installed Hook\n"); 
    }

    enable_write_protection();
    return exec_memory;
}

bool uninstall_hook(void) {   
   if(exec_memory && do_syscall_64 && orig_do_syscall_64) {
        pr_info("Unhooking...\n"); 
        pr_info("do_syscall_64 %px\n", do_syscall_64);

        disable_write_protection();

        DUMP_MEMORY(do_syscall_64, DUMP_SIZE);
        pr_info("orig_do_syscall_64 %px\n", (void*)orig_do_syscall_64); 

        memcpy(do_syscall_64, (void*)orig_do_syscall_64, INST_ALIGNED);
        DUMP_MEMORY(do_syscall_64, DUMP_SIZE);
        #ifdef USE_VMALLOC
        vfree(exec_memory);
        #endif
        enable_write_protection();
        pr_info("Uninstalled Hook\n"); 
        return true;
    }
    return false;
}


MODULE_LICENSE("GPL");