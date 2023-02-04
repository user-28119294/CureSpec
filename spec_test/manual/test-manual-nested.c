#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int*);
extern void __is_tainted(int);
extern int nd();
extern bool spec_nd(int);
extern bool fence_nd(int);

unsigned int array1_size = 16;
int array1[16];

//extern bool __spec_fn(int i);
__attribute__ ((noinline)) bool __spec_fn(int i) {
    return fence_nd(i);
}

int main(int argn, char* args[]) {
    int source;
    int temp = 0;

    bool spec = false;
    bool start_spec = false;
    bool assume_cond = true;

    source = nd();
    __taint(&source);

    start_spec = spec_nd(0);
    if (nd()) {
        assume_cond = spec | ((source < array1_size) ^ start_spec);
        assume(assume_cond);
        spec |= start_spec;
        spec &= __spec_fn(0);
        assume(!spec); // fence, does *not* prevent the error

        start_spec = spec_nd(1);
        if (nd()) {
            assume_cond = spec | ((source < array1_size) ^ start_spec);
            assume(assume_cond);
            spec |= start_spec;
            spec &= __spec_fn(1);
            //assume(!start_spec);

            sassert(!spec);
            temp = array1[source];
        }
    }

    return temp;
}

