/* EXAMPLE 9:  Use a separate value to communicate the safety check status. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __taint_ptr(int*);
extern void __is_tainted(int);
extern int nd();
extern int *nd_ptr();

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
    int *is_safe = nd_ptr();
    __taint(source);
    __taint_ptr(is_safe);

    if (*is_safe)
        temp &= array2[array1[source] * 512];

    return 0;
}
