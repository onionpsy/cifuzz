#include "trigger_bugs.h"

#include <string>
#include <string.h>

using namespace std;

void triggerASan() {
  // Trigger a heap buffer overflow
  char *s = (char *)malloc(1);
  strcpy(s, "too long");
  printf("%s\n", s);
}

void triggerUBSan() {
  // Trigger the undefined behavior sanitizer
  int n = 23;
  n <<= 32;
}
