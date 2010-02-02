#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <utime.h>
#include <com_err.h>
#include <profile.h>

int nthreads = 10;
unsigned int delay = 3600;

volatile int done = 0; /* XXX hack */

const char *path = "/tmp/foo1.conf:/tmp/foo.conf";
const char *filename = "/tmp/foo.conf";

const char *prog;

static void *worker(void *arg)
{
    profile_t p;
    long err;
    int i;
    const char *const names[] = {
	"one", "two", "three", 0
    };
    char **values;
    const char *mypath = (random() & 1) ? path : filename;

    while (!done) {
	err = profile_init_path(mypath, &p);
	if (err) {
	    com_err(prog, err, "calling profile_init(\"%s\")", mypath);
	    exit(1);
	}
	for (i = 0; i < 10; i++) {
	    values = 0;
	    err = profile_get_values(p, names, &values);
	    if (err == 0 && values != 0)
		profile_free_list(values);
	}
	profile_release(p);
    }
    return 0;
}

static void *modifier(void *arg)
{
    struct timespec req;
    while (!done) {
	req.tv_sec = 0;
	req.tv_nsec = random() & 499999999;
	nanosleep(&req, 0);
	utime(filename, 0);
/*	printf("."), fflush(stdout); */
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int i;
    pthread_t thr;

    prog = argv[0];
    for (i = 0; i < nthreads; i++) {
	assert(0 == pthread_create(&thr, 0, worker, 0));
    }
    sleep(1);
    pthread_create(&thr, 0, modifier, 0);
    sleep(delay);
    done = 1;
    sleep(2);
    return 0;
}
