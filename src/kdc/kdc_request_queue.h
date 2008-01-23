#ifdef USE_THREADS

#include "k5-int.h"
#include "kdc_util.h"

#define MAX_PENDING_REQ 50

typedef struct _kdc_request_t {
	krb5_data *request;
	krb5_data *response;
	krb5_fulladdr *from;
	krb5_fulladdr *to_addr;
	int transport;
	int sockfd;
	struct _kdc_request_t *next;
} kdc_request_t;

krb5_error_code init_queue(void);
void destroy_queue(void);
krb5_error_code add_to_req_queue(kdc_request_t *);
kdc_request_t *get_req_from_queue(void);

#endif /* USE_THREADS */

