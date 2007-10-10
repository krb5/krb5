/*
    simple_lock_test.c
    
    Initializes two contexts in two different threads and tries to get read locks on both at the same time.
    Hangs at line 24.
*/
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <Kerberos/CredentialsCache.h>

void * other_thread ()
{
    cc_int32 err;
    cc_context_t context = NULL;
    
    err = cc_initialize(&context, ccapi_version_7, NULL, NULL);

    fprintf(stderr, "thread: attempting lock. may hang. err == %d\n", err);

    if (!err) {
        // hangs with cc_lock_read which should succeed immediately, but does not hang with write, upgrade, and downgrade, which fail immediately
        err = cc_context_lock(context, cc_lock_read, cc_lock_noblock);
    }

    if (context) {
        cc_context_unlock(context);
        cc_context_release(context);
        context = NULL;
    }
    fprintf(stderr, "thread: return. err == %d\n", err);
}


int main (int argc, char *argv[])
{
    cc_int32 err;
    int status;
    pthread_t thread_id;
    cc_context_t context = NULL;
    
    err = cc_initialize(&context, ccapi_version_7, NULL, NULL);
    if (!err) {
        err = cc_context_lock(context, cc_lock_read, cc_lock_noblock);
    }
    
    fprintf(stderr, "main: initialized and read locked context. err == %d\n", err);

    status = pthread_create (&thread_id, NULL, (void *) other_thread, NULL);
    if (status != 0) {
        fprintf(stderr,"Create error!\n");
        exit(-1);
    }

    pthread_join(thread_id, NULL);
    
    fprintf(stderr, "main: unlocking and releasing context. err == %d\n", err);
    
    if (context) {
        cc_context_unlock(context);
        cc_context_release(context);
        context = NULL;
    }

    fprintf(stderr, "main: return. err == %d\n", err);
    
    return 0;
}