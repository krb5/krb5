#ifdef USE_THREADS

#include <assert.h>
#include "k5-int.h"
#include "extern.h"

#include "kdc_request_queue.h"

static struct _kdc_request_queue_t {
    int n, max;

    pthread_cond_t not_full, not_empty;
    k5_mutex_t mut;

    kdc_request_t *req_queue_head;
} req_queue;

krb5_error_code init_queue(void)
{
    int ret;

    req_queue.n = 0;
    req_queue.max = (MAX_PENDING_REQ >= thread_count) ? MAX_PENDING_REQ : thread_count;

    ret = pthread_cond_init(&req_queue.not_full, NULL);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while initializing not_full condition");
	return ret;
    }

    ret = pthread_cond_init(&req_queue.not_empty, NULL);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while initializing not_empty condition");
	return ret;
    }

    ret = k5_mutex_init(&req_queue.mut);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while initializing mutex");
	return ret;
    }

    req_queue.req_queue_head = NULL;

    return 0;
}

void destroy_queue(void)
{
    kdc_request_t *ptr;

    /* Cleanup mutexes */
    pthread_cond_destroy(&req_queue.not_full);
    pthread_cond_destroy(&req_queue.not_empty);
    k5_mutex_destroy(&req_queue.mut);

    /* Cleanup the request queue */
    while (req_queue.req_queue_head != NULL) {
	ptr = req_queue.req_queue_head;
	req_queue.req_queue_head = ptr->next;
	if (ptr->from != NULL)
	    krb5_free_address(def_kdc_context, ptr->from->address);
	krb5_free_data(def_kdc_context, ptr->request);
	krb5_free_data(def_kdc_context, ptr->response);
	free(ptr);
    }
}

krb5_error_code add_to_req_queue(kdc_request_t *req)
{
    int ret;
    kdc_request_t **pptr;

    req->next = NULL;

    ret = k5_mutex_lock(&req_queue.mut);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while locking queue mutex");
	return ret;
    }

    /*
     * req_queue.mut.os.p is available only on linux. There is no k5_* wrapper
     * for pthread_cond_wait.
     */
    while (req_queue.n == req_queue.max) {
	ret = pthread_cond_wait(&req_queue.not_full, &req_queue.mut.os.p);
	if (ret != 0) {
	    com_err("krb5kdc", ret, "while waiting on queue not_full condition");
	    return ret;
	}
    }

    pptr = &req_queue.req_queue_head;

    while (*pptr != NULL)
	pptr = &(*pptr)->next;

    *pptr = req;

    req_queue.n++;

    ret = pthread_cond_signal(&req_queue.not_empty);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while signalling queue not_empty condition");
	return ret;
    }

    ret = k5_mutex_unlock(&req_queue.mut);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while unlocking queue mutex");
	return ret;
    }

    return 0;
}

kdc_request_t *get_req_from_queue(void)
{
    krb5_error_code ret;
    kdc_request_t *ptr = NULL;

    ret = k5_mutex_lock(&req_queue.mut);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while locking queue mutex");
	return NULL;
    }

    while (req_queue.n == 0) {
	ret = pthread_cond_wait(&req_queue.not_empty, &req_queue.mut.os.p);
	if (ret != 0) {
	    com_err("krb5kdc", ret, "while waiting on queue not_empty condition");
	    return NULL;
	}

#ifdef DEBUG_THREADS
	req_queue.mut.os.owner = pthread_self();
#endif
    }

    ptr = req_queue.req_queue_head;

    req_queue.req_queue_head = req_queue.req_queue_head->next;
    req_queue.n--;

    ret = pthread_cond_signal(&req_queue.not_full);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while signalling queue not_full condition");
	return NULL;
    }

    ret = k5_mutex_unlock(&req_queue.mut);
    if (ret != 0) {
	com_err("krb5kdc", ret, "while unlocking queue mutex");
	return NULL;
    }

    ptr->next = NULL;

    return ptr;
}

#endif /* USE_THREADS */
