/* handle having mutually exclusive termio vs. termios */
/* return 0 if handled */
#ifdef	STREAMSPTY
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/ioctl.h>
#include <termios.h>
#if !defined(TCSETS) && defined(_AIX) /* kludge for AIX */
#include <termio.h>
#endif

int readstream_termios(cmd, ibuf, vstop, vstart, ixon)
     int cmd;
     char *ibuf;
     char *vstop, *vstart;
     int *ixon;
{
  struct termios *tsp;
  switch (cmd) {
  case TCSETS:
  case TCSETSW:
  case TCSETSF:
    tsp = (struct termios *)
      (ibuf+1 + sizeof(struct iocblk));
    *vstop = tsp->c_cc[VSTOP];
    *vstart = tsp->c_cc[VSTART];
    *ixon = tsp->c_iflag & IXON;
    return 0;
  }
  return -1;
}

#else
int silence_warnings_about_empty_source_file_termios = 42;
#endif /* STREAMSPTY */
