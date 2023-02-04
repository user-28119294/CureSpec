/* EXAMPLE 2:  Moving the leak to a local function that can be inlined. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __is_tainted(int);
extern int nd();

// avoid optimizations
extern void init(void*);

/*  Moving the leak to a local inlined function. */

const unsigned int array1_size = 16;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 1;

void leak_byte_local_function(uint8_t k) {
    temp &= array2[k * 512];
}

int main(int argn, char* args[]) {
    init(array1);
    init(array2);

    unsigned source = nd();
    __taint(source);
    if (source < array1_size) {
        leak_byte_local_function(array1[source]);
    }
    return 0;
}
