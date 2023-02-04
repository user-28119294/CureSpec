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

int main(int argn, char* args[]) {
    unsigned source;
    uint8_t temp = 0;

    source = nd();
    __taint(source);
    if (source < array1_size) {
        temp = array2[array1[source] * 512];
    }

    return temp;
}

