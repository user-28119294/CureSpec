#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16; 
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;

struct data_t {
    int a;
    uint8_t *pdata1;
    uint8_t *pdata2;
};


/* Use strcuture */
void victim_fun(int idx) {
    struct data_t msg;
    msg.pdata1 = (uint8_t*)array1;
    msg.pdata2 = (uint8_t*)array2;

    if (idx < array1_size) {
        msg.a = *(msg.pdata1 + idx);
        temp |= *(msg.pdata2 + msg.a);
    }   
}


void main(int argn, char* args[]) {
    int source;
    FILE *file = fopen("temp.txt", "r");

    if (file == NULL)
        return;
    source = fgetc(file);
    victim_fun(source);
}

