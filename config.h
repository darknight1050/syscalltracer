#define HOOK_PARAMS (struct pt_regs *regs, int nr)

//#define USE_VMALLOC

#define INST_ALIGNED 15 //MIN 13

#define DUMP_SIZE 0x100

#define DUMP_MEMORY(...)
//#define DUMP_MEMORY(...) dump_memory(__VA_ARGS__)