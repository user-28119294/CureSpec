/* EXAMPLE 10:  Leak a comparison result. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(unsigned);
extern void __taint_8(uint8_t);
extern void __is_tainted(int);
extern int nd();

// avoid optimizations
extern void init(void*);

const unsigned int array1_size = 16;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 1;

int main(int argn, char* args[]) {
    init(array1);
    init(array2);

    unsigned source = nd();
    uint8_t k = nd();
    __taint(source);
    __taint_8(k);

    if (source < array1_size) {
        if (array1[source] == k)
            temp &= array2[0];
    }
    return 0;
}
