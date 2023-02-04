#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int*);
extern void __is_tainted(int);
extern int nd();
extern bool spec_nd(int);
extern bool fence_nd();

//char fixed[2] = {0, 0};
//int spec_val[2];

unsigned int array1_size = 16;
int array1[16];

//__attribute__ ((noinline)) bool spec_fn(int i) {
//  if (fixed[i]) { return spec_val[i]; }
//  int new_spec_val = nd();
//  spec_val[i] = new_spec_val;
//  fixed[i] = 1;
//  return new_spec_val;
//}

//extern bool __spec_fn(int i);
__attribute__ ((noinline)) bool __spec_fn_0() {
    return fence_nd();
}

__attribute__ ((noinline)) bool __spec_fn_1() {
    return fence_nd();
}

int main(int argn, char* args[]) {
    int source;
    int temp = 0;

    source = nd();
    __taint(&source);

    bool spec = false;
    bool start_spec = false;
    bool assume_cond = true;

    start_spec = spec_nd(0);
    if (nd()) {
        assume_cond = spec | ((source < array1_size) ^ start_spec);
        assume(assume_cond);
        spec |= start_spec;
        spec &= __spec_fn_0();
        assume(!spec); // fence, does *not* prevent the error

        start_spec = spec_nd(1);
        if (nd()) {
            assume_cond = spec | ((source < array1_size) ^ start_spec);
            assume(assume_cond);
            spec |= start_spec;
            spec &= __spec_fn_1();
            //assume(!spec);

            sassert(!spec);
            temp = array1[source];
        }
    }

    return temp;
}

