#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __is_tainted(int);
extern int nd();

const unsigned int array1_size = 16;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;

int main(int argn, char* args[]) {
    int source;

    source = nd();
    __taint(source);
    uint8_t *p1 = (uint8_t*)array1;

    if (source < array1_size) {
        temp = source;
    }
    else temp = nd();

    temp |=  array2[*(p1 + source)*512];

    return 0;
}






