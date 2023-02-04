#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <seahorn/seahorn.h>

extern void __taint(int);
extern void __is_tainted(int);
extern int nd();
extern void spec_fence();

// avoid optimization of array
extern void init(void*);
extern int permute(int, unsigned);

const unsigned int array1_size = 16;
int array1[16];

int main(int argn, char* args[]) {
    init(array1);

    int source;
    int temp = 0;
    int unrelated;

    unrelated = nd();
    source = nd();
    __taint(unrelated);
    __taint(source);

    //spec_fence();
    if (source < array1_size) {
        // one fence here suffices
        // However, having one fence each in the following branches should not
        // increase the overhead, because only one is executed.
        //
        //spec_fence();
        if (unrelated) {
            temp = array1[source];
        } else {
            temp = array1[permute(source, array1_size)];
        }
    }

    return temp;
}

