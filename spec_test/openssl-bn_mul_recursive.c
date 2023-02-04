#include <stddef.h>
#include <string.h>
#include "openssl.h"
#include <seahorn/seahorn.h>

extern void __taint(BN_ULONG*);
extern void __taint_int(int);

extern BN_ULONG *nd_ulong();
extern int nd();
extern void display(void*);
extern void display_int(int);

#ifndef OPENSSL_SMALL_FOOTPRINT
# define BN_MUL_COMBA
# define BN_SQR_COMBA
# define BN_RECURSION
#endif

#define OPENSSL_BN_ASM_PART_WORDS

#include "openssl-bn_mul_impl.h"

int main() {
 // BN_CTX *ctx = BN_CTX_new();
//  __taint(ctx);
  BN_ULONG *r = nd_ulong();
  BN_ULONG *a = nd_ulong();
  BN_ULONG *b = nd_ulong();
  BN_ULONG *t = nd_ulong();
  int n2 = nd();
  int dna = nd();
  int dnb = nd();

  __taint(r);
//  __taint(a);
//  __taint(b);
//  __taint(t);
//  __taint_int(n2);
//  __taint_int(dna);
//  __taint_int(dnb);

  bn_mul_recursive(r, a, b, n2, dna, dnb, t);

  // to avoid optimizations
  display(r);
  display(a);
  display(b);
  display(t);
  display_int(n2);
  display_int(dna);
  display_int(dnb);
  return 0;
}
