/* Header file for encrypted-stream library.
 * Written by Ken Raeburn (Raeburn@Cygnus.COM).
 * Copyright (C) 1991, 1992, 1994 by Cygnus Support.
 *
 * Permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation.
 * Cygnus Support makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef K5STREAM_H
#define K5STREAM_H

typedef struct {                                /* Object we pass around */
    int fd;                                     /* Open socket descriptor */
} *kstream;

typedef void *kstream_ptr;                      /* Data send on the kstream */

struct kstream_data_block {
    kstream_ptr ptr;
    size_t length;
};

struct kstream_crypt_ctl_block {
    int (INTERFACE *encrypt) (
      struct kstream_data_block *, /* output -- written */
		struct kstream_data_block *, /* input */
		kstream str);
    int (INTERFACE *decrypt) (
      struct kstream_data_block *, /* output -- written */
      struct kstream_data_block *, /* input */
      kstream str);
    int (INTERFACE *init) (kstream str, kstream_ptr data);
    void (INTERFACE *destroy) (kstream str);
};


/* Prototypes */

int kstream_destroy (kstream);
void kstream_set_buffer_mode (kstream, int);
kstream kstream_create_from_fd (int fd,
				const struct kstream_crypt_ctl_block __far *ctl,
				kstream_ptr data);
int kstream_write (kstream, void __far *, size_t);

#endif /* K5STREAM_H */
