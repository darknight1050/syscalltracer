#include "utils.h"
#include <linux/module.h> 

#ifdef CONFIG_KPROBES
#define HAVE_KPROBES 1 
#include <linux/kprobes.h> 
#else 
#define HAVE_PARAM 1 
#include <linux/kallsyms.h>
#endif /* CONFIG_KPROBES */ 

void dump_memory(void* address, size_t size)
{
    pr_info("Memory dump with size %ld at address: %px\n", size, address); 
    for(size_t i = 0; i<size;i += 8) {
        pr_info("%02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X\n", *(((char*)address)+i), *(((char*)address)+i+1), *(((char*)address)+i+2), *(((char*)address)+i+3), *(((char*)address)+i+4), *(((char*)address)+i+5), *(((char*)address)+i+6), *(((char*)address)+i+7)); 
    }
    pr_info("Finished memory dump\n"); 
}

void* search_code_cave(void* start, size_t search_size, size_t size)
{
    size_t current_size = 0;
    for(size_t i = 0; i < search_size; i++) {
        if((current_size == 0 && ((char*)start)[i] == 0xC3) || (current_size > 0 && (((char*)start)[i] == 0x90 || ((char*)start)[i] == 0xCC))) {
            if(++current_size == size+1) {
                return &((char*)start)[i-current_size+1];
            }
        } else {
            current_size = 0;
        }
    }
    return NULL;
}

static inline void __write_cr0(unsigned long cr0) 
{ 
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory"); 
} 

void enable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    set_bit(16, &cr0); 
    __write_cr0(cr0); 
} 
 
void disable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    clear_bit(16, &cr0); 
    __write_cr0(cr0); 
}

void* _kallsyms_lookup_name(const char* name) {
    #ifdef HAVE_KPROBES 
    pr_info("HAVE_KPROBES\n");
    unsigned long (*kallsyms_lookup_name)(const char *name); 
    struct kprobe kp = { 
        .symbol_name = "kallsyms_lookup_name", 
    }; 
 
    if (register_kprobe(&kp) < 0) 
        return 0; 
    kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr; 
    unregister_kprobe(&kp); 
    #endif
    return (void*)kallsyms_lookup_name(name);
}

MODULE_LICENSE("GPL");