#include <stdio.h>
#include <com_err.h>
#include <krb5.h>
#include "k5-int.h"
#include <pthread.h>

krb5_context ctx;
krb5_rcache rcache;
krb5_data piece = { .data = "hello", .length = 5 };
time_t end_time;
const char *prog;

struct tinfo {
    time_t now;
    unsigned long my_ctime;
    unsigned int my_cusec;
    unsigned int total;
    int idx;
};

#undef INIT_ONCE

static void try_one (struct tinfo *t)
{
    krb5_donot_replay r;
    krb5_error_code err;
    char buf[100], buf2[100];
    krb5_rcache my_rcache;

    sprintf(buf, "host/all-in-one.mit.edu/%p@ATHENA.MIT.EDU", buf);
    r.server = buf;
    r.client = (t->my_cusec & 7) + "abcdefgh@ATHENA.MIT.EDU";
    if (t->now != t->my_ctime) {
	if (t->my_ctime != 0) {
	    sprintf(buf2, "%3d: %ld %5d\n", t->idx, t->my_ctime, t->my_cusec);
	    printf("%s", buf2);
	}
	t->my_ctime = t->now;
	t->my_cusec = 1;
    } else
	t->my_cusec++;
    r.ctime = t->my_ctime;
    r.cusec = t->my_cusec;
#ifndef INIT_ONCE
    err = krb5_get_server_rcache(ctx, &piece, &my_rcache);
    if (err) {
	com_err(prog, err, "getting replay cache");
	exit(1);
    }
#else
    my_rcache = rcache;
#endif
    err = krb5_rc_store(ctx, my_rcache, &r);
    if (err) {
	com_err(prog, err, "storing in replay cache");
	exit(1);
    }
#ifndef INIT_ONCE
    krb5_rc_close(ctx, my_rcache);
#endif
}

static void *run_a_loop (void *x)
{
    struct tinfo t = { 0 };
/*    int chr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"[(*(int*)x) % 27]; */

    t.now = time(0);
    t.idx = *(int *)x;
    while (t.now != time(0))
	;
    t.now = time(0);
    while (t.now < end_time) {
	t.now = time(0);
	try_one(&t);
	t.total++;
/*	printf("%c", chr); */
	fflush(stdout);
    }
    printf("thread %p total %u\n", &t, t.total);
    *(int*)x = t.total;
    return 0;
}

int main (int argc, char *argv[])
{
    int n;
    krb5_error_code err;
    int interval = 20 /* 5 * 60 */;

    prog = argv[0];
    unlink("/var/tmp/rc_hello_7882");
    unlink("/var/tmp/hello_7882");
    n = 2;
    err = krb5_init_context(&ctx);
    if (err) {
	com_err(prog, err, "initializing context");
	return 1;
    }
#ifdef INIT_ONCE
    err = krb5_get_server_rcache(ctx, &piece, &rcache);
    if (err) {
	com_err(prog, err, "getting replay cache");
	return 1;
    }
#endif
    end_time = time(0) + interval;
#undef DIRECT
#ifdef DIRECT
    {
	int zero = 0;
	run_a_loop(&zero);
    }
#else
    {
	int i, *ip;

	ip = malloc(sizeof(int) * n);
	if (ip == 0 && n > 0) {
	    perror("malloc");
	    exit(1);
	}
	for (i = 0; i < n; i++)
	    ip[i] = i;

	for (i = 0; i < n; i++) {
	    pthread_t new_thread;
	    int perr;
	    perr = pthread_create(&new_thread, 0, run_a_loop, &ip[i]);
	    if (perr) {
		errno = perr;
		perror("pthread_create");
		exit(1);
	    }
	}
	while (time(0) < end_time + 1)
	    sleep(1);
	for (i = 0; i < n; i++)
	    printf("thread %d total %5d\n", i, ip[i]);
    }
#endif
    return 0;
}
