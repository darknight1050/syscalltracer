#include <linux/kernel.h> 

void dump_memory(void* address, size_t size);
void* search_code_cave(void* start, size_t search_size, size_t size);

void enable_write_protection(void);
void disable_write_protection(void);
void* _kallsyms_lookup_name(const char* name);