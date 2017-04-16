
// these come from src/pkg/runtime/proc.c
extern void syscall·runtime_BeforeFork(void);
extern void syscall·runtime_AfterFork(void);

void ·BeforeFork(void) {
    syscall·runtime_BeforeFork();
}

void ·AfterFork(void) {
    syscall·runtime_AfterFork();
}
