/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YSTATE_H
#define YSTATE_H

#ifdef YARROW_SAVE_STATE

#include "ycipher.h"
#include "ytypes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Yarrow_STATE {
    byte seed[CIPHER_KEY_SIZE * 2];    /* 2k bits saved to seed file */
} Yarrow_STATE;

int STATE_Save( const char *filename, const struct Yarrow_STATE* state );
int STATE_Load( const char *filename, struct Yarrow_STATE* state );

#ifdef __cplusplus
}
#endif

#endif /* YARROW_SAVE_STATE */

#endif /* YSTATE_H */
