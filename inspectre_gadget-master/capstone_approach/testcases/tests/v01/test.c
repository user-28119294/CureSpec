#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16; 
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;



/* Use pointer to replace array */
void victim_fun(int idx) {
    uint8_t *p1 = &array1[0];
    uint8_t *p2 = &array2[0];
    int tmp;

    if (idx < array1_size) {
        p1 = p1 + idx;
        tmp = *p1;
        tmp *= 512;
        p2 = p2 + tmp;
        temp += *p2;
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

