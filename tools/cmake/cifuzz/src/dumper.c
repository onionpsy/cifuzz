#include <stddef.h>
#include <string.h>

#ifdef __APPLE__
#include <dlfcn.h>
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

static const char UBSAN_SUMMARY_PREFIX[] = "SUMMARY: UndefinedBehaviorSanitizer:";
static void (*sanitizer_death_callback)(void) = NULL;

/*
 * By linking this file into a fuzz test (and adding a linker flag on Linux),
 * non-fatal sanitizer findings will still write an input to disk.
 *
 * For both macOS and Linux, we hook:
 * - __sanitizer_set_death_callback, to which libFuzzer provides a callback that
 *   can be used to dump the current input;
 * - __sanitizer_report_error_summary, which is executed by all sanitizers on a
 *   finding, regardless of whether it is fatal. Since this function is provided
 *   the summary line, we can call __sanitizer_set_death_callback only if
 *   needed.
 */
#ifdef __APPLE__
/*
 * On macOS, sanitizers are exclusively linked dynamically, which allows us to
 * wrap functions simply by defining them and looking up the original function
 * via dlsym(RTLD_NEXT, ...). We can't use the --wrap linker flag since the
 * macOS linker doesn't support it.
 */
void __sanitizer_set_death_callback(void (*callback)(void)) {
  sanitizer_death_callback = callback;
  void *real_sanitizer_set_death_callback =
    dlsym(RTLD_NEXT, "__sanitizer_set_death_callback");
  ((void (*)(void (*)()))(real_sanitizer_set_death_callback))(callback);
}

/*
 * Ensure that ASan's verify_interceptors check passes: It checks that puts and
 * __sanitizer_report_error_summary are defined in the same object. Since we
 * hook the latter, we also have to (trivially) hook the former.
 * https://github.com/llvm/llvm-project/blob/f8a469fc572778d05b72f34a772082cf3abd3cda/compiler-rt/lib/sanitizer_common/sanitizer_mac.cpp#L987-L993
 * Older versions of LLVM check for pthread_create instead:
 * https://github.com/llvm/llvm-project/blob/abc51fac09593ec048b3b298fa274af823e0a22d/compiler-rt/lib/sanitizer_common/sanitizer_mac.cpp#L1061-L1067
 */
int puts(const char *str) {
  void *real_puts = dlsym(RTLD_NEXT, "puts");
  return ((int (*)(const char *))(real_puts))(str);
}

int pthread_create(pthread_t *thread,
                   const pthread_attr_t *attr,
                   void *(*start_routine)(void *),
                   void *arg) {
  void *real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
  return ((int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *))(real_pthread_create))(thread, attr, start_routine, arg);
}

void __sanitizer_report_error_summary(const char *error_summary) {
  void *real_sanitizer_report_error_summary =
    dlsym(RTLD_NEXT, "__sanitizer_report_error_summary");
  ((void (*)(const char *))(real_sanitizer_report_error_summary))(error_summary);
  if (strncmp(UBSAN_SUMMARY_PREFIX, error_summary, strlen(UBSAN_SUMMARY_PREFIX)) == 0) {
    sanitizer_death_callback();
  }
}
#else
/*
 * On Linux, the --wrap flag of GNU ld can be used to wrap all calls to a given
 * function. We can't use the macOS approach as sanitizer runtimes can be linked
 * statically.
 */
void __real___sanitizer_set_death_callback(void (*callback)(void));

void __wrap___sanitizer_set_death_callback(void (*callback)(void)) {
  sanitizer_death_callback = callback;
  __real___sanitizer_set_death_callback(callback);
}

/* clang mangling applied to __sanitizer::Printf(const char *format, ...) */
void _ZN11__sanitizer6PrintfEPKcz(const char *format, ...);

/*
 * If wrapped with --wrap, the __wrap_ version of this function is never called.
 * It is not clear why. Instead, we inline the real implementation of this
 * function, which consists of a single call to an internal implementation of
 * Printf.
 */
void __sanitizer_report_error_summary(const char *error_summary) {
  _ZN11__sanitizer6PrintfEPKcz(error_summary);
  if (sanitizer_death_callback == NULL) {
    return;
  }
  /*
   * Do not emit the input twice for ASan, which is always fatal.
   * TODO: This will change if we introduce --recover-asan.
   * TODO: Since we do not take the state of --recover-ubsan into account, we
   *  dump the input twice with --recover-ubsan=false. This is harmless as it
   *  only pollutes the verbose flags, but should still be fixed.
   */
  if (strncmp(UBSAN_SUMMARY_PREFIX, error_summary, strlen(UBSAN_SUMMARY_PREFIX)) == 0) {
    sanitizer_death_callback();
  }
}
#endif

#ifdef __cplusplus
}
#endif
