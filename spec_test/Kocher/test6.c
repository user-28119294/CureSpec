/* EXAMPLE 6:  Check the bounds with an AND mask, rather than "<". */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __is_tainted(int);
extern int nd();

// avoid optimizations
extern void init(void*);

// const unsigned int array1_size = 16;
const unsigned int array_size_mask = 15;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;


int main(int argn, char* args[]) {
    init(array1);
    init(array2);

    unsigned source = nd();
    __taint(source);
    if ((source & array_size_mask) == source) {
        temp &= array2[array1[source] * 512];
    }
    return 0;
}
