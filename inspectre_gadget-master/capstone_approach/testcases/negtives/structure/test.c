#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

unsigned int array1_size = 16; 
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;


void victim_fun(int idx) {
    if (idx < array1_size) {    
        temp &= array2[array1[idx] * 512];
    }   
}

struct s_t {
	int size;
	char buf[100];
};

int main(int argc, char *argv[]) {
	FILE *fp = fopen("test.txt", "r");
	struct s_t *tt;
    int ret;

	tt = (struct s_t*)malloc(sizeof(struct s_t));

    
    ret = recv(0, tt->buf, 100, 1) ;
	tt->size = ret;

	if (tt != NULL) {
		temp |= tt->buf[0];
	}
	
	return 0;
}
