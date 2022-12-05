#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <cifuzz/cifuzz.h>

FUZZ_TEST(const uint8_t *data, size_t size) {
  if (size < 1) {
    return;
  }
  switch (data[0]) {
    case 'A':
      printf("%s\n", "A");
      break;
    case 'B':
      printf("%s\n", "B");
      break;
    case 'C':
      printf("%s\n", "C (assert failure)");
      assert(1 == 0);
      break;
    case 'D':
      printf("%s\n", "D");
      break;
    case 'E':
      printf("%s\n", "E");
      break;
    case 'F':
      printf("%s\n", "F (exit)");
      exit(1);
      break;
    case 'G':
      printf("%s\n", "G");
      break;
    case 'H':
      printf("%s\n", "H");
      break;
    case 'I':
      printf("%s\n", "I (segfault)");
      *((volatile char *) 0) = 1;
      break;
    case 'J':
      printf("%s\n", "J");
      break;
  }
}
