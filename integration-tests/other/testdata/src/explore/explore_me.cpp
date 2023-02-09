#include "explore_me.h"
#include "bug/trigger_bugs.h"

// just a function with multiple paths that can be discoverd by a fuzzer
void exploreMe(int a, int b, std::string c) {
  if (a >= 20000) {
    if (b >= 2000000) {
      if (b - a < 100000) {
        if (c == "FUZZING") {
          triggerASan();
        }
      } else {
        triggerUBSan();
      }
    }
  }
}
