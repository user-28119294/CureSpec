#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

unsigned int array1_size = 16; 
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;


void victim_fun(int idx) {
    if (idx < array1_size) {                  
        temp &= array2[array1[idx] * 512];
    }   
}

int main(int argc, char* argv[]) {
    uint8_t buffer[100];
    int taint;

    recv(0, buffer, 100, 1);
    taint = (int)buffer;
    victim_fun(taint);
   return 0;
}
