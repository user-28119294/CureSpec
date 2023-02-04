/* Standard Spectre-PHT but nested */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __is_tainted(int);
extern int nd();
extern void f();

// avoid optimization of array
extern void init(void*);

const unsigned int array1_size = 16;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 1;

int main(int argn, char* args[]) {
    init(array1);
    init(array2);

    int source;
    int x;
//    bool access_granted;

    source = nd();
    x = nd();
//    access_granted = nd();

    __taint(source);
    __taint(x);
//    __taint(access_granted);

    if (source < array1_size) {
//      if (access_granted) {
//        temp &= array2[array1[source] * 512];
        f();
        if (x < array1_size) {
            temp &= array2[array1[x] * 512];
        }
    }
    return 0;
}
