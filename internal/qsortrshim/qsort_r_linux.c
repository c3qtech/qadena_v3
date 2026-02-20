#define _GNU_SOURCE
#include <stdlib.h>

/*
 * glibc qsort_r signature:
 *   int compar(const void*, const void*, void* arg)
 */
struct qsort_r_ctx {
    int (*compar)(const void*, const void*, void*);
    void *arg;
};

static __thread struct qsort_r_ctx g_ctx;  // thread-local so it's safe with concurrency

static int thunk(const void *a, const void *b) {
    return g_ctx.compar(a, b, g_ctx.arg);
}

void qsort_r(void *base, size_t nmemb, size_t size,
             int (*compar)(const void *, const void *, void *),
             void *arg)
{
    g_ctx.compar = compar;
    g_ctx.arg = arg;
    qsort(base, nmemb, size, thunk);
}