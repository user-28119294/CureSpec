#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "openssl-aes.h"

/* This controls loop-unrolling in aes_core.c */
// #define FULL_UNROLL
#define OPENSSL_NO_AES_CONST_TIME

#include "openssl-aes_core_impl.h"

#define ARRAY_SIZE 64

void init_array(unsigned char *a, FILE *file) {
  for (int i = 0; i < ARRAY_SIZE; ++i) {
    *a = fgetc(file);
    ++a;
  }
}

void display(unsigned char *a) {
  printf("%c", a[0]);
  printf("%c", a[1]);
  printf("%c", a[2]);
  printf("%c", a[3]);
  printf("%c", a[4]);
  printf("%c", a[5]);
  printf("%c", a[6]);
  printf("%c", a[7]);
  printf("%c", a[8]);
  printf("%c", a[9]);
  printf("%c", a[10]);
  printf("%c", a[11]);
  printf("%c", a[12]);
  printf("%c", a[13]);
  printf("%c", a[14]);
  printf("%c", a[15]);
}

int main() {
  FILE *file = fopen("temp.txt", "r");

  if (file == NULL) {
    printf("No file!");
    return 0;
  }

  unsigned char in[ARRAY_SIZE];
  unsigned char out[ARRAY_SIZE];
  init_array(in, file);
  init_array(out, file);

  AES_KEY *key = (AES_KEY*) fgetc(file);

  AES_encrypt(in, out, key);

  // to avoid optimizations
  display(in);
  display(out);
  return 0;
}
