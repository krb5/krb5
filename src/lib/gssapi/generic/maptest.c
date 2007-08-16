#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

typedef struct { int a, b; } elt;
static int eltcp(elt *dest, elt src)
{
    *dest = src;
    return 0;
}
static int eltcmp(elt left, elt right)
{
    if (left.a < right.a)
	return -1;
    if (left.a > right.a)
	return 1;
    if (left.b < right.b)
	return -1;
    if (left.b > right.b)
	return 1;
    return 0;
}
static void eltprt(elt v, FILE *f)
{
    fprintf(f, "{%d,%d}", v.a, v.b);
}

#include "maptest.h"

foo foo1;

int main ()
{
    int err;
    elt v1 = { 1, 2 }, v2 = { 3, 4 };
    long idx;
    int added;

    err = foo_init(&foo1);
    assert(err == 0);
    err = foo_find_or_append(&foo1, v1, &idx, &added);
    assert(err == 0);
    printf("v1: idx=%ld added=%d\n", idx, added);
    err = foo_find_or_append(&foo1, v2, &idx, &added);
    assert(err == 0);
    printf("v2: idx=%ld added=%d\n", idx, added);
    err = foo_find_or_append(&foo1, v2, &idx, &added);
    assert(err == 0);
    printf("v2: idx=%ld added=%d\n", idx, added);
    err = foo_find_or_append(&foo1, v1, &idx, &added);
    assert(err == 0);
    printf("v1: idx=%ld added=%d\n", idx, added);
    return 0;
}
