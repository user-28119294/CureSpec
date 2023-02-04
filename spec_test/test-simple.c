/* Standard Spectre-PHT */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __is_tainted(int);
extern void spec_fence();
extern int nd();

const unsigned int array1_size = 16;
uint8_t array1[16];
uint8_t array2[256 * 512];

uint8_t x;

int main(int argn, char* args[]) {
    int source;
    int temp = 0;

    source = nd();
    __taint(source);

//    spec_fence();
    if (source < array1_size) {
        array1[source] = nd();
        x = array1[source];
//        sassert(x < 5);
        temp = array2[x * 512];
    }
    return temp;
}
