/*  EXAMPLE 5:  Use x as the initial value in a for() loop. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
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
    __taint(source);

    if (source < array1_size) {
        for (int i = source - 1; i >= 0; i--)
            temp &= array2[array1[i] * 512];
    }
    return 0;
}
