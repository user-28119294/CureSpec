#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16; 
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;

/*  Mixed pointer and array */
void victim_fun(int idx) {
    uint8_t *p1 = (uint8_t*) array1;
    if (idx < 10) {
        temp |=  array2[*(p1 + idx)*512];
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

