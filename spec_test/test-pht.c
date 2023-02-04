/* Standard Spectre-PHT */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __is_tainted(int);
extern void spec_fence();
extern int nd();

// avoid optimization of array
extern void init(void*);

const unsigned int array1_size = 16;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 1;

int main(int argn, char* args[]) {
    // init arrays
    init(array1);
    init(array2);


    int source;
    source = nd();
    __taint(source);

    if (source < array1_size) {
//        temp &= array2[array1[source] * 512];
        temp &= array1[source];
    }
    return 0; // temp;
}
