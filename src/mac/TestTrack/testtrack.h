/*
 *   Copyright (C) 1992 by the Massachusetts Institute of Technology
 *   All rights reserved.
 *
 *   For copying and distribution information, please see the file
 *   COPYRIGHT.
 */
/*
 * Function prototypes for testtrack routines
 */


OSErr tt_open_MacTCP(short *drvrRefNum); 	/* Pass NULL if you feel like it*/


/* function prototypes from tt.c */
void tt_acknowledge(char *control, ...);
void tt_fatal_error(char *control, ...);
void tt_ensure(OSErr errcode, char *message);
int tt_edit_user_info(struct tt_user_info **user);
void tt_install_callback (int (*callback)(struct v_pkt *));
int test_track(char *appl_name, char *appl_vers, Boolean edit_flag,
	       Boolean do_logging, int check_probability);


/* function prototypes from vlib.c */
void v_parse_pkt (struct v_pkt *pkt, struct v_info *info);
int v_read_pkt (int sock, struct v_pkt *pkt, struct v_info *info,
		struct sockaddr *sa, int *sockaddr_len);
int v_assemble_pkt (struct v_pkt *pkt, struct v_info *info);
