/*                            KITEST-MASTER.C				    */
/*									    */
/* Program to build GSSAPI-compliant Kerberos authentication packets, using */
/* the Kerberos V5 (Beta 2) GSSAPI implementation, and attempt to	    */
/* authenticate to a DCE/GSSAPI implementation.				    */
/*									    */
/* Since both GSSAPI implementations share the same routine names, two	    */
/* executables are built by linking against either the DCE/GSSAPI or the    */
/* Kerberos V5 GSSAPI library.  This file is compiled with the preprocessor */
/* name KERBEROS defined if it is to invoke the Kerberos API, and with DCE  */
/* defined if it is to link against the DCE/GSSAPI.			    */
/*									    */
/* Invocation should specify two parameters -				    */
/* 1) Name of initiating principal					    */
/* 2) Name of accepting principal					    */
/*									    */
/* A flag '-S' is used to specify the name of the file that process will    */
/* activate as a slave.							    */
/*									    */
/* So to test, for example, Kerberos against Kerberos, and assuming that    */
/* the executable is called kitest-krb, you'd set up a Kerberos credential  */
/* for <client-name> using kinit, and arrange for a server Kerberos         */
/* credential for <server-name> to be available in a keytable, and issue    */
/* the command:                                                             */
/*       kitest-krb -S kitest-krb <client-name> <server-name>               */
/*                                                                          */
/* The original process becomes the context initiator, while the spawned    */
/* subprocess (running the executable specified after the -S flag) is       */
/* expected to act as the context acceptor.                                 */

#if defined(KERBEROS) && defined(DCE)
#error "Both KERBEROS and DCE specified"
#endif

#if !defined(KERBEROS) && !defined(DCE)
#error "Neither KERBEROS nor DCE defined"
#endif 

/* You need to create links from krb-gssapi.h to the Kerberos gssapi.h, and  */
/* from dce-gssapi.h to the DCE gssapi.h.                                    */
#ifdef KERBEROS
#include "krb-gssapi.h"
#endif

#ifdef DCE
#include "dce-gssapi.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <netdb.h>

#ifndef GSS_ERROR
#define GSS_ERROR(x) (x & 0xffff0000)
/* The Kerberos gssapi.h doesn't define this macro.                         */
#endif

#define DOWN_CHANNEL 3
/* Don't understand why stdin doesn't work here, but channel 3 seems to     */
/* work fine.                                                               */

#define INITIAL_CHILD_MESSAGES 7

extern int errno;

int master = 0;
int inpipe[2];
int outpipe[2];
int errpipe[2];

gss_name_t source_internal_name;
gss_name_t target_internal_name;
gss_name_t source_authenticated_name;
gss_buffer_desc source_name_buffer;
gss_buffer_desc target_name_buffer;

gss_cred_id_t my_cred_handle;
gss_cred_id_t delegated_cred_handle;
gss_ctx_id_t my_ctx_handle;
gss_OID_set actual_cred_mech_set;
gss_OID actual_ctx_mech_type;
OM_uint32 actual_cred_time_rec;
OM_uint32 actual_ctx_time_rec;
gss_buffer_desc token_to_send;
gss_buffer_desc token_received;
int actual_ret_flags;
struct gss_channel_bindings_struct my_channel_bindings;

char source_name[512];        
char target_name[512];        

char my_host_name[50];
char my_internet_address[4];
struct hostent * my_hostent;

unsigned char received_token_buffer[2048];
unsigned received_length;

OM_uint32 major_status;
OM_uint32 kept_status;
OM_uint32 minor_status;

int subprocess_pid = 0;

char line_buffer[128];    
int chars_read;

void indicate_data(void) {
    fprintf(stderr, "\a\n");
    fflush(stderr);    
}

void send_data(void * ptr, unsigned length) {
    unsigned char length_buf[2];
    unsigned char * char_ptr;
    int data_sent;
    
    char_ptr = (unsigned char *)ptr;
    
    length_buf[0] = length & 0xff;
    length_buf[1] = (length & 0xff00) >> 8;

    if (master) {
/* Data is sent via inpipe.						    */
	errno = 0;
	if ((data_sent = write(inpipe[1], length_buf, 2)) != 2) {
	    fprintf(stderr,
		    "Write of length sent %d bytes, expected 2\n",
	    	    data_sent);
	    fflush(stderr);
	    if (data_sent == -1) {
		fprintf(stderr,
			"Errno: %d\n",
			errno);
		fflush(stderr);
	    };
	};
	errno = 0;
	if ((data_sent =write(inpipe[1], ptr, length)) != length) {
	    fprintf(stderr,
		    "Write of length sent %d bytes, expected 2\n",
	    	    data_sent);
	    fflush(stderr);
	    if (data_sent == -1) {
		fprintf(stderr,
			"Errno: %d\n",
			errno);
		fflush(stderr);
	    };
	};
	fprintf(stderr, "Sending data (length = %d):\n", length);
	fprintf(stderr, "  %2.2X %2.2X %2.2X %2.2X %2.2X...\n",
		char_ptr[0], char_ptr[1], char_ptr[2],
		char_ptr[3], char_ptr[4]);
    } else {
/* Data is sent via stdout, and a data indication on stderr.		    */
	fwrite(length_buf, 2, 1, stdout);
	fwrite(ptr, length, 1, stdout);
	fflush(stdout);
	indicate_data();
    };
}

void receive_data(void * ptr, unsigned * length) {
    unsigned char length_buf[2];
    unsigned char * char_ptr;
    int data_read;
    
    char_ptr = (unsigned char *)ptr;
    
    if (master) {
/* Data is received via outpipe.  A data indication is assumed to have been */
/* received on errpipe, otherwise this routine will hang.		    */
	read(outpipe[0], length_buf, 2);
	*length = length_buf[0] | (length_buf[1]<<8);
	read(outpipe[0], ptr, *length);
    } else {
/* Data is received on fd3						    */
	errno = 0;
	if ((data_read = read(DOWN_CHANNEL, length_buf, 2)) != 2) {
	    fprintf(stderr,
		    "Error: received %d bytes for length, expecting 2\n",
		    data_read);
	    fflush(stderr);
	    if (data_read == -1) {
		fprintf(stderr, "errno: %d\n", errno);
		fflush(stderr);
	    };
	};

	*length = length_buf[0] | (length_buf[1]<<8);

	errno = 0;
	if ((data_read = read(DOWN_CHANNEL, ptr, *length)) != *length) {
	    fprintf(stderr,
		    "Error: received %d bytes for data, expecting %d\n",
		    data_read, *length);
	    fflush(stderr);
	    if (data_read == -1) {
		fprintf(stderr, "errno: %d\n", errno);
		fflush(stderr);
	    };
	};

	fprintf(stderr, "Received data (length = %d):\n", *length);
	fprintf(stderr, "  %2.2X %2.2X %2.2X %2.2X %2.2X...\n",
		char_ptr[0], char_ptr[1], char_ptr[2],
		char_ptr[3], char_ptr[4]);

    };
}

int read_subproc_line(char * ptr, unsigned buf_length) {
/* Returns length of data read, or zero if binary data waiting.		    */
    int bytes_read = 0;
    int finished = 0;
    if (!master) {
	fprintf(stderr, "Error: Child called read_subproc_data\n");
	fflush(stderr);
	exit(2);
    } else {
	while (!finished) {
	    read(errpipe[0], &ptr[bytes_read], 1);
	    if (ptr[bytes_read] == '\n') finished = 1;
	    if (bytes_read >= buf_length) finished = 1;
	    bytes_read ++;
	};
	if (bytes_read == 2 && ptr[0] == '\a') return 0;
	else return bytes_read;
    };
}

void display_error(char * where, OM_uint32 maj_stat, OM_uint32 min_stat) {
    int context = 0;
    OM_uint32 major_status, minor_status;
    gss_buffer_desc message_buffer;

    fprintf(stderr, "Error: %s\n", where);
    fprintf(stderr, "Major status (%d) (min = %d):\n", maj_stat, min_stat);
    fflush(stderr);
    do {
	message_buffer.length = 0;
	message_buffer.value = NULL;
	major_status = gss_display_status(&minor_status,
					  maj_stat,
					  GSS_C_GSS_CODE,
					  GSS_C_NULL_OID,
					  &context,
					  &message_buffer);
	fprintf(stderr, 
	    " message_buffer.length = %u, message_buffer.value = %p\n",
	    message_buffer.length, message_buffer.value);
	fflush(stderr);
	if (message_buffer.length = 0) {
	    fprintf(stderr,
		    " %.*s\n",
		    message_buffer.length,
		    message_buffer.value);
	    major_status = gss_release_buffer(&minor_status, &message_buffer);
	} else {
	    fprintf(stderr, "-- no message --\n");
            /* If we've been asked to translate an invalid status code */
	};
	fflush(stderr);

    } while (context != 0);
    fprintf(stderr, "Minor status:\n");
    fflush(stderr);
    major_status = gss_display_status(&minor_status,
				      min_stat,
				      GSS_C_MECH_CODE,
				      GSS_C_NULL_OID,
				      &context,
				      &message_buffer);
    fprintf(stderr,
	    " %.*s\n",
	    message_buffer.length,
	    message_buffer.value);
    fflush(stderr);
    
    major_status = gss_release_buffer(&minor_status, &message_buffer);

}

void import_names(void) {

    source_name_buffer.value = (void *)&source_name[0];
    source_name_buffer.length = strlen(source_name);

    major_status = gss_import_name(&minor_status,
				   &source_name_buffer,
				   GSS_C_NULL_OID,
				   &source_internal_name);

    if (major_status != GSS_S_COMPLETE)
	display_error("Importing source principal", major_status, minor_status);

    target_name_buffer.value = (void *)&target_name[0];
    target_name_buffer.length = strlen(target_name);

    major_status = gss_import_name(&minor_status,
				   &target_name_buffer,
				   GSS_C_NULL_OID,
				   &target_internal_name);

    if (major_status != GSS_S_COMPLETE)
	display_error("Importing target principal", major_status, minor_status);

}


void alarm_handler(int sig) {
    fprintf(stderr, "SIGALRM received, terminating subprocess\n");
    fflush(stderr);
    kill(subprocess_pid, SIGTERM);
    exit(0);
}


void flush_subprocess_message_queue_and_exit(void) {

    signal(SIGALRM, alarm_handler);
    alarm(10);	    

    do {
	chars_read = read_subproc_line(line_buffer,
				       sizeof(line_buffer));
	if (chars_read == 0) {
	    fprintf(stderr,
		    "Unexpected binary data received from child\n");
	    fflush(stderr);
	    receive_data(received_token_buffer,
			 &received_length);
	} else {
	    fprintf(stderr,"CHILD> %.*s", chars_read, line_buffer);
	};
	fflush(stderr);
    } while (1);
}

void sigpipe_handler(int sig) {
    fprintf(stderr, "SIGPIPE received, flushing subprocess message queue\n");
    fflush(stderr);
    flush_subprocess_message_queue_and_exit();
}

int main(int argc, char *argv[]) {

    int c;
    int errflg = 0;
    char * image_name;
    int pid;

    int i;
    
    extern int optind, opterr;
    extern char * optarg;

    int blocking;
    
    while ((c = getopt(argc, argv, "S:")) != EOF) {
	switch (c) {
	case 'S' : master = 1;
		   image_name = optarg;
		   break;
	case '?' : errflg++;
		   break;
	};
    };

    if (optind < argc) {
	strncpy(source_name, argv[optind++], sizeof(source_name)-1);
    } else {
	fprintf(stderr, "Error: Source name (prin-1) missing\n");
	errflg++;
    };

    if (optind < argc) {
	strncpy(target_name, argv[optind++], sizeof(source_name)-1);
    } else {
	fprintf(stderr, "Error: Target name (prin-2) missing\n");
	errflg++;
    };

    if (optind < argc) {
	fprintf(stderr, "Error: too many parameters\n");
	errflg++;
    };

    if (errflg) {
	fprintf(stderr, "Usage: %s -S <subprocess> <princ-1> <princ-2>\n", argv[0]);
	exit(2);
    };

    gethostname(my_host_name, sizeof(my_host_name));
    my_hostent = gethostbyname(my_host_name);
    memcpy(&my_internet_address, my_hostent->h_addr_list[0], 4);

    fprintf(stderr,"Host: '%s', %u.%u.%u.%u\n", 
	    my_host_name, 
	    my_internet_address[0],
	    my_internet_address[1],
	    my_internet_address[2],
	    my_internet_address[3]);

    my_channel_bindings.initiator_addrtype = GSS_C_AF_INET;
    my_channel_bindings.initiator_address.length = 4;
    my_channel_bindings.initiator_address.value = my_internet_address;

    my_channel_bindings.acceptor_addrtype = GSS_C_AF_INET;
    my_channel_bindings.acceptor_address.length = 4;
    my_channel_bindings.acceptor_address.value = my_internet_address;

    my_channel_bindings.application_data.length = 0;
    my_channel_bindings.application_data.value = NULL;

    my_ctx_handle = GSS_C_NO_CONTEXT;

    if (!master) {

/* Subprocess.								    */

	fprintf(stderr, "Importing names\n");
	fflush(stderr);

	import_names();

	fprintf(stderr, "Calling acquire_cred\n");
	fflush(stderr);

	major_status = gss_acquire_cred(&minor_status,
					target_internal_name,
					60 * 60 * 24,
					GSS_C_NULL_OID_SET,
					GSS_C_ACCEPT,
					&my_cred_handle,
					&actual_cred_mech_set,
					&actual_cred_time_rec);

	if (major_status != GSS_S_COMPLETE) {
	    display_error("Acquiring ACCEPT credential for target principal",
			   major_status, minor_status);
	    while (1) ;
	};
	
	fprintf(stderr, "Returned from acquire_cred, waiting for token from parent\n");
	fflush(stderr);

	do {

	    receive_data(received_token_buffer,
			 &received_length);
	    token_received.value = (void *)received_token_buffer; 
	    token_received.length = received_length; 
	    
	    fprintf(stderr, "Got token, calling accept_sec_context\n");
	    fflush(stderr);

	    major_status = gss_accept_sec_context(&minor_status,
						 &my_ctx_handle,
						 my_cred_handle,
						 &token_received,
						 &my_channel_bindings,
						 &source_authenticated_name,
						 &actual_ctx_mech_type,
						 &token_to_send,
						 &actual_ret_flags,
						 &actual_ctx_time_rec,
						 &delegated_cred_handle);
	    kept_status = major_status;

	    if (GSS_ERROR(major_status)) {
		display_error("ACCEPT_SEC_CONTEXT",
			       major_status, minor_status);
		while (1) ;
	    };
	    	
	    if (token_to_send.length != 0) {
		send_data(token_to_send.value, token_to_send.length);
		major_status = gss_release_buffer(&minor_status,
						  &token_to_send);
	    };

	    if (kept_status & GSS_S_CONTINUE_NEEDED) {
		receive_data(received_token_buffer,
			     &received_length);
		token_received.value = (void *)received_token_buffer; 
		token_received.length = received_length; 
	    };

	} while (kept_status & GSS_S_CONTINUE_NEEDED);	

	if (!GSS_ERROR(kept_status)) {
	    fprintf(stderr, "Authenticated context established\n");
	} else {
	    fprintf(stderr, "Context not established\n");
	};
	fflush(stderr);
	while (1) ;
    } else {
/* We need to create three pipes - inpipe, outpipe and errpipe, to which    */
/* the subprocess will connect its fd3, stdout and stderr channels.	    */

	if (pipe(inpipe) < 0) {
	    fprintf(stderr, "Error: Can't make inpipe\n");
	    exit(2);
	};
	if (pipe(outpipe) < 0) {
	    fprintf(stderr, "Error: Can't make outpipe\n");
	    exit(2);
	};
	if (pipe(errpipe) < 0) {
	    fprintf(stderr, "Error: Can't make errpipe\n");
	    exit(2);
	};

	if ((subprocess_pid = fork()) == 0) {
/* This is the slave subprocess in a two-process chain.  Connect inpipe,    */
/* outpipe and errpipe to fd3, stderr and stdout, and then exec the slave */
/* image.								    */
	    fprintf(stderr, "CHILD: forked, closing pipes\n");
	    fflush(stderr);

	    close(inpipe[1]);  /* Close write end of inpipe		    */
	    close(outpipe[0]); /* Close read end of outpipe		    */
	    close(errpipe[0]); /* Close read end of errpipe		    */


	    write (errpipe[1],
		    "Child process forked (write to errpipe[1])\n",
		    strlen("Child process forked (write to errpipe[1])\n")
		  );

	    if (dup2(inpipe[0], DOWN_CHANNEL) == -1) {
		fprintf(stderr, "CHILD: Can't dup2 inpipe[0]\n");
		fflush(stderr);
	    };
		/* Attach inpipe to fd3		    */
	    if (dup2(outpipe[1], 1) == -1) {
		fprintf(stderr, "CHILD: Can't dup2 outpipe[1]\n");
		fflush(stderr);
	    };
		/* Attach outpipe to stdout		    */
	    if (dup2(errpipe[1], 2) == -1) {
		fprintf(stderr, "CHILD: Can't dup2 errpipe[1]\n");
		fflush(stderr);
	    };
		 /* Attach errpipe to stderr		    */
	    
	    write (2,
		    "Child process forked (write to fd2)\n",
		    strlen("Child process forked (write to fd2)\n")
		  );
		    
	    fprintf(stderr, "Execing %s\n", image_name);
	    fflush(stderr);

	    execl(image_name, image_name, source_name, target_name,  (char *)0);

	    fprintf(stderr, "Error: Couldn't exec %s\n", image_name);
	    exit(2);

	} else if (subprocess_pid < 0) {
	    fprintf(stderr, "Error: Fork returned %d\n", subprocess_pid);
	    exit(2);
	} else {
/* This is the master process in a two-process chain.  The slave process    */
/* has connected inpipe, outpipe and errpipe to its fd3, stdout and	    */
/* stderr.  We have to use the other ends.				    */


	    close(inpipe[0]);  /* Close read end of inpipe		    */
	    close(outpipe[1]); /* Close write end of outpipe		    */
	    close(errpipe[1]); /* Close write end of errpipe		    */

/* A simple protocol will be used between master and slave processes.  The  */
/* subprocess (slave) will always expect that data received on its inpipe   */
/* will be binary messages, preceeded by a two-byte count.  Messages from   */
/* slave to master will be sent on the errpipe channel if they are text	    */
/* messages, and on outpipe if they are binary data (preceeded as above by  */
/* a two-byte count field).  The presence of a binary message in the	    */
/* outpipe will be indicated by writing the sequence "\a\n" to errpipe.	    */
/* This protocol is implemented in the master by the routine		    */
/* read_subproc_line, which reads a single line of text from the	    */
/* subprocess, returning either its length, or zero to indicate that binary */
/* data is waiting.  Binary data is received by either process by invoking  */
/* the receive_data routine, and sent by invoking the send_data routine.    */
/* The receive_data routine will block until the data is available, so	    */
/* care should be taken in the master not to call this routine unless a	    */
/* data indication has already been received.				    */

/* Master:								    */
	    signal(SIGPIPE, sigpipe_handler);

/* The child will send us messages on start-up (at least                    */
/* INITIAL_CHILD_MESSAGES of them), so we'll read them here to make sure we */
/* catch a sleepy child early.                                              */

	    fprintf(stderr, "Parent waiting for wake-up call from child...\n");
	    fflush(stderr);

	    signal(SIGALRM, alarm_handler);
	    alarm(10);	    

	    for (i=0; i<INITIAL_CHILD_MESSAGES; i++) {
		chars_read = read_subproc_line(line_buffer,
					       sizeof(line_buffer));

		if (chars_read == 0) {
		    fprintf(stderr,
			    "Unexpected binary data received from child\n");
		    fflush(stderr);
		    receive_data(received_token_buffer,
				 &received_length);
		} else {
		    fprintf(stderr,"CHILD> %.*s", chars_read, line_buffer);
		};
		fflush(stderr);

	    };
	    
	    alarm(0);

	    fprintf(stderr, "Parent continuing, importing names...\n");
	    fflush(stderr);

	    import_names();
				       
	    fprintf(stderr, "Parent got names...\n");
	    fflush(stderr);

#ifdef KERBEROS

/* This version of the acquire_cred code requests the client credential     */
/* explicitly by name; the DCE version uses no name, meaning "give me a     */
/* to the default credential.                                               */

	    fprintf(stderr, "Parent calling acquire_cred...\n");
	    fflush(stderr);

	    major_status = gss_acquire_cred(&minor_status,
					    source_internal_name,
					    60 * 60 * 24,
					    GSS_C_NULL_OID_SET,
					    GSS_C_INITIATE,
					    &my_cred_handle,
					    &actual_cred_mech_set,
					    &actual_cred_time_rec);

	    fprintf(stderr, "Parent returned from acquire_cred.\n");
	    fflush(stderr);

#endif
#ifdef DCE
	    major_status = gss_acquire_cred(&minor_status,
					    GSS_C_NO_NAME,
					    60 * 60 * 24,
					    GSS_C_NULL_OID_SET,
					    GSS_C_INITIATE,
					    &my_cred_handle,
					    &actual_cred_mech_set,
					    &actual_cred_time_rec);
#endif
	    if (major_status != GSS_S_COMPLETE)
		display_error("Acquiring INITIATE credential for source principal",
			       major_status, minor_status);


	    token_received.length = 0;
	    token_received.value = NULL;
	    
	    do {

		fprintf(stderr, "Parent calling init_sec_ctx...\n");
		fflush(stderr);

		major_status = gss_init_sec_context(&minor_status,
						    my_cred_handle,
						    &my_ctx_handle,
						    target_internal_name,
						    GSS_C_NULL_OID,
						    GSS_C_MUTUAL_FLAG,
						    60 * 60 * 23,
						    &my_channel_bindings,
						    &token_received,
						    &actual_ctx_mech_type,
						    &token_to_send,
						    &actual_ret_flags,
						    &actual_ctx_time_rec);

		fprintf(stderr, "Parent returned from init_sec_ctx...\n");
		fflush(stderr);

		kept_status = major_status;
    
		if (GSS_ERROR(major_status))
		    display_error("INIT_SEC_CONTEXT",
				   major_status, minor_status);
		
		if (token_to_send.length != 0) {

		    fprintf(stderr, "Parent transmitting token...\n");
		    fflush(stderr);

		    send_data(token_to_send.value, token_to_send.length);
		    major_status = gss_release_buffer(&minor_status,
						      &token_to_send);
		};

		if (kept_status & GSS_S_CONTINUE_NEEDED) {
		    signal(SIGALRM, alarm_handler);
		    alarm(30);
		    while ((chars_read = read_subproc_line(line_buffer,
    							  sizeof(line_buffer))
			   ) != 0) {
			fprintf(stderr, "CHILD> %.*s", chars_read, line_buffer);
		    };
		    alarm(0);
		    receive_data(received_token_buffer,
			         &received_length);
		    token_received.value = (void *)received_token_buffer; 
		    token_received.length = received_length; 
		};

	    } while (kept_status & GSS_S_CONTINUE_NEEDED);	

	    if (!GSS_ERROR(kept_status)) {
		fprintf(stderr, "Authenticated context established\n");
	    } else {
		fprintf(stderr, "Context not established\n");
	    };
	    fflush(stderr);

	    flush_subprocess_message_queue_and_exit();
   
	};
    };
}
