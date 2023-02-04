#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;



/* IMs has not control dependency with CB */
void victim_fun(int idx) {
    uint8_t *p1 = (uint8_t*)array1;
    uint8_t *p2 = (uint8_t*)array2;

    if (idx < array1_size) {
        temp = idx;
    }

    temp |=  array2[*(p1 + idx)*512];
}

int main(int argn, char* args[]) {
    int source;

    FILE *file = fopen("temp.txt", "r");

    if (file == NULL)
        return 0;

    source = fgetc(file);
    victim_fun(source);

    return 0;
}






