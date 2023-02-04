/* EXAMPLE 7:  Compare against the last known-good value. */
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

    static unsigned last_x = 0;
    if (source == last_x)
        temp &= array2[array1[source] * 512];
    if (source < array1_size)
        last_x = source;

    return 0;
}
