#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <sys/sdt.h>

int main(int argc, char const *argv[]) {
    DTRACE_PROBE(hello-usdt, probe-main);
    return 0;
}

