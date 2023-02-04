#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int*);
extern void __is_tainted(int);
extern int nd();
extern bool spec_nd(int);
extern bool fence_nd();

unsigned int array1_size = 16;
int array1[16];

__attribute__ ((noinline)) bool fence_0() {
    return fence_nd();
    //return true;
}

__attribute__ ((noinline)) bool fence_1() {
    return fence_nd();
    //return true;
}

__attribute__ ((noinline)) bool fence_2() {
    return fence_nd();
    //return true;
}

int main(int argn, char* args[]) {
    int unrelated;
    int source;
    int temp = 0;

    unrelated = nd();
    source = nd();
    __taint(&unrelated);
    __taint(&source);

    bool spec = false;
    bool start_spec = false;
    bool assume_cond = true;

    start_spec = spec_nd(0);
    if (nd()) {
        //assume_cond = spec | ((source < array1_size) ^ start_spec);
        assume_cond = ((source < array1_size) ^ start_spec);
        assume(assume_cond);
        spec |= start_spec;
        assume(!(spec & fence_0()));
        //
        // One fence here suffices to prevent leakage.
        // However, having one fence each in the following branches is also fine
        // and should not increase the overhead, because only one is executed.
        //
        // Our method is not happy with one fence here. The reason is that it
        // does not look at the condition that gets speculatively ignored. Thus,
        // since the unrelated condition can start speculation it signals a
        // possible leak.
        // If we have fences in both inner branches, then our method confirms
        // that the program is free from leakage.
        //
        start_spec = spec_nd(1);
        if (nd()) {
            //assume_cond = spec | (unrelated ^ start_spec);
            assume_cond = (unrelated ^ start_spec);
            assume(assume_cond);
            spec |= start_spec;
            assume(!(spec & fence_1()));

            sassert(!spec);
            //sassert(source < array1_size);
            temp = array1[source];
        } else {
            //assume_cond = spec | ((!unrelated) ^ start_spec);
            assume_cond = ((!unrelated) ^ start_spec);
            assume(assume_cond);
            spec |= start_spec;
            assume(!(spec & fence_2()));

            sassert(!spec);
            //sassert(source < array1_size);
            temp = array1[source];
        }
    }

    return temp;
}

