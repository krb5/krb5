/* handle having mutually exclusive termio vs. termios */
/* return 0 if handled */
#ifdef	STREAMSPTY
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/ioctl.h>
#include <termio.h>

int readstream_termio(cmd, ibuf, vstop, vstart, ixon)
     int cmd;
     char *ibuf;
     char *vstop, *vstart;
     int *ixon;
{
  struct termio *tp;
  switch (cmd) {
  case TCSETA:
  case TCSETAW:
  case TCSETAF:
    tp = (struct termio *) (ibuf+1 + sizeof(struct iocblk));
#if 0				/* VSTOP/VSTART only in termios!? */
    *vstop = tp->c_cc[VSTOP];
    *vstart = tp->c_cc[VSTART];
#endif
    *ixon = tp->c_iflag & IXON;      
    return 0;
  }
  return -1;
}

#else
int silence_warnings_about_empty_source_file_termio = 42;
#endif /* STREAMSPTY */
