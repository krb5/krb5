/* 
 * Copyright 1994, The University of Texas at Austin
 * All rights reserved.
 */

#define authType 'TNae'					/* auth/encrypt module resource type */
#define moduleType 'TNae'				/* auth/encrypt module file type */

#define NTMPAIRS	10					/* max type/modifier pairs */

#define	IAC	255
#define	SB	250
#define	SE	240

#define BOGUS 0x50015001

/*
 * Kerberos, encryption
 */
#define OPT_AUTHENTICATION 37
#define OPT_ENCRYPT 38

#define KRB_REJECT		1		/* Rejected (reason might follow) */
#define KRB_AUTH		0		/* Authentication data follows */
#define KRB_ACCEPT		2		/* Accepted */
#define KRB_CHALLENGE	3		/* Challenge for mutual auth */
#define KRB_RESPONSE	4		/* Response for mutual auth */

#define TNQ_IS			0		/* Option is ... */
#define TNQ_SEND		1		/* send option */
#define TNQ_REPLY		2		/* suboption reply */
#define TNQ_NAME		3		/* suboption name */

/*
* AUTHENTICATION option types
*/
#define AUTH_NULL        0      /* no authentication */
#define AUTH_KERBEROS_V4 1      /* Kerberos version 4 */
#define AUTH_KERBEROS_V5 2      /* Kerberos version 5 */

/*
* AUTHENTICATION option modifiers
*/
#define AUTH_WHO_MASK         1
#define AUTH_CLIENT_TO_SERVER 0
#define AUTH_SERVER_TO_CLIENT 1
#define AUTH_HOW_MASK         2
#define AUTH_HOW_ONE_WAY      0
#define AUTH_HOW_MUTUAL       2

/*
 * suboption buffer offsets 
 */
#define SB_OPTION    0			/* option byte */
#define SB_SUBOPTION 1          /* is, send, reply, name */
#define SB_TYPE      2          /* authentication type */
#define SB_MODIFIER  3          /* type modifier */
#define SB_DATATYPE  4          /* type of data */
#define SB_DATA      5          /* offset to first data byte */

/*
 * ENCRYPTION suboptions
 */
#define	ENCRYPT_IS			0	/* I pick encryption type ... */
#define	ENCRYPT_SUPPORT		1	/* I support encryption types ... */
#define	ENCRYPT_REPLY		2	/* Initial setup response */
#define	ENCRYPT_START		3	/* Am starting to send encrypted */
#define	ENCRYPT_END			4	/* Am ending encrypted */
#define	ENCRYPT_REQSTART	5	/* Request you start encrypting */
#define	ENCRYPT_REQEND		6	/* Request you send encrypting */
#define	ENCRYPT_ENC_KEYID	7
#define	ENCRYPT_DEC_KEYID	8
#define	ENCRYPT_CNT			9

#define	ENCTYPE_ANY			0
#define	ENCTYPE_DES_CFB64	1
#define	ENCTYPE_DES_OFB64	2
#define	ENCTYPE_CNT			3

/* 
 * authentication or encryption module entry point 
 */
typedef long (*module)(long func, void *parameters);

/*
 * TNAE functions.
 */
enum {
	TNFUNC_INIT_SESSION_AUTH = 1,		/* init auth session data */
	TNFUNC_INIT_SESSION_ENCRYPT,		/* init encrypt session data */
	TNFUNC_QUERY_ENCRYPT,				/* query encryption capability */
	TNFUNC_INIT_CODE,					/* init code module */
	TNFUNC_AUTH_SEND,					/* process auth send sub-option */
	TNFUNC_AUTH_REPLY,					/* process auth reply sub-option */
	TNFUNC_ENCRYPT_SB,					/* process encryption sub-options */
	TNFUNC_DECRYPT,						/* decrypt data */
	TNFUNC_ENCRYPT						/* encrypt data */
};


/*
 * TN code module return codes
 */
enum {
	TNREP_OK = 0,						/* no error */
	TNREP_START_DECRYPT,				/* start decrypting (not an error) */
	TNREP_AUTH_OK,						/* authentication ok */
	TNREP_AUTH_ERR,						/* authentication rejected */
	TNREP_ERROR,						/* generic error */
	TNREP_NOMEM							/* no memory */
};


/*
 * Parameters
 */
typedef struct tnParams_ {
	void *authdata;						/* auth data */
	void *encryptdata;					/* encrypt data */

	/* parameters for auth/encrypt_suboption */
	unsigned char *subbuffer;			/* sub options buffer */
	unsigned long sublength;
	unsigned char *sendbuffer;			/* buffer to return option data */
	unsigned long *sendlength;			/* length of return buffer */
	Boolean hisencrypt;					/* his encrypt option state */
	Boolean myencrypt;					/* my encrypt option state */
	char *cname;						/* pointer to cannonical hostname */

	/* used by authencrypt.c */
	module entry;						/* auth/encrypt code module entry point */

	/* data and flags for client */
	Boolean encrypting;					/* we are encrypting */
	Boolean startencrypting;			/* time to start encrypting */
	Boolean decrypting;					/* we are decrypting */
	long data;							/* for encrypt/decrypt */
	unsigned char *ebuf;				/* encrypt buf */
} tnParams;



