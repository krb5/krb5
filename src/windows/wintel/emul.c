#include "windows.h"
#include "screen.h"

/**********************************************************************
*  Function :   ScreenEmChar
*  Purpose  :   Send a character to the virtual screen with no translantion
*  Parameters   :
            fpScr - pointer top screen
*           c - character to send to the virtual screen
*  Returns  :   none
*  Calls    :
*  Called by    :   ScreenEm()
**********************************************************************/
static int ScreenEmChar(SCREEN *fpScr,unsigned char c)
{
    int sx;
    int insert,
        ocount,
        attrib,
        extra,
        offend;
    char *acurrent,         /* pointer to the attributes for characters drawn */
        *current,           /* pointer to the place to put characters */
        *start;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;

    hgScrLine=GetScreenLineFromY(fpScr,fpScr->y);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
    if (fpScrLine==NULL) return (-1);

    current=start=&fpScrLine->text[fpScr->x];
    acurrent=&fpScrLine->attrib[fpScr->x];

    attrib=fpScr->attrib;
    insert=fpScr->IRM;          /* boolean */
    ocount=fpScr->x;
    offend=0;
    extra=0;
    sx=fpScr->x;
    if(fpScr->x>fpScr->width) {
        if(fpScr->DECAWM) {  /* check for line wrapping on */
            fpScr->x=0;
            ScreenIndex(fpScr);
        } /* end if */
        else                /* no line wrapping */
            fpScr->x=fpScr->width;
        current=start=&fpScrLine->text[fpScr->x];
        acurrent=&fpScrLine->attrib[fpScr->x];
        ocount=fpScr->x;
        sx=fpScr->x;
    } /* end if */
    if(insert)
        ScreenInsChar(fpScr,1);
    *current=c;
    *acurrent=(char)attrib;
    if(fpScr->x<fpScr->width) {
        acurrent++;
        current++;
        fpScr->x++;
    } /* end if */
    else {
        if(fpScr->DECAWM) {
            fpScr->x++;
            offend=1;
        } /* end if */
        else {
            fpScr->x=fpScr->width;
            extra=1;
        } /* end else */
    } /* end else */
    if(insert)
        ScreenInsString(fpScr,fpScr->x-ocount+offend+extra,start);        /* actually just decides which RS to use */
    else
        ScreenDraw(fpScr,sx,fpScr->y,fpScr->attrib,fpScr->x-ocount+offend+extra,start);
    LINE_MEM_UNLOCK(hgScrLine);        
}   /* end ScreenEmChar() */

void ScreenEm(LPSTR c,int len,HSCREEN hsScr)
{
    HSCREENLINE hgScrLine;
    SCREEN *fpScr;
    SCREENLINE *fpScrLine;    
    int escflg;             /* vt100 escape level */
    RECT rc;
	unsigned int ic;
	char stat[20];
	int i;
    
    fpScr=(SCREEN *) GlobalLock(hsScr);
    if (fpScr==NULL) {
        OutputDebugString("Screen is hosed.\r\n");
        return;
    }

    if (fpScr->screen_bottom != fpScr->buffer_bottom) {
		ScreenUnscroll(fpScr);
        InvalidateRect(fpScr->hWnd,NULL,TRUE);
        SetScrollPos(fpScr->hWnd,SB_VERT,fpScr->numlines,TRUE);
	}

    ScreenCursorOff(fpScr);
    escflg=fpScr->escflg;

#ifdef UM
/* @UM */
    if(fpScr->localprint && (len>0)) {    /* see if printer needs anything */
        pcount=send_localprint(c,len);
        len-=pcount;
        c+=pcount;
      } /* end if */
/* @UM */
#endif

    while(len>0) {
        while((*c<32) && (escflg==0) && (len>0)) {      /* look at first character in the vt100 string, if it is a non-printable ascii code */
            switch(*c) {
            
                case 0x1b:      /* ESC found (begin vt100 control sequence) */
                    escflg++;
                    break;

				case -1:		/* IAC from telnet session */
					escflg=6;
					break;

#ifdef CISB
                case 0x05:      /* CTRL-E found (answerback) */
                    bp_ENQ();
                    break;

#endif
                case 0x07:      /* CTRL-G found (bell) */
                    ScreenBell(fpScr);
                    break;

                case 0x08:      /* CTRL-H found (backspace) */
                    ScreenBackspace(fpScr);
                    break;

                case 0x09:          /* CTRL-I found (tab) */
                    ScreenTab(fpScr);       /* Later change for versatile tabbing */
                    break;

                case 0x0a:          /* CTRL-J found (line feed) */
                case 0x0b:          /* CTRL-K found (treat as line feed) */
                case 0x0c:          /* CTRL-L found (treat as line feed) */
                    ScreenIndex(fpScr);
                    break;
                case 0x0d:      /* CTRL-M found (carriage feed) */
                    ScreenCarriageFeed(fpScr);
                    break;

#ifdef LATER
                case 0x0e:      /* CTRL-N found (invoke Graphics (G1) character set) */
                    if(fpScr->G1)
                        fpScr->attrib=VSgraph(fpScr->attrib);
                    else
                        fpScr->attrib=VSnotgraph(fpScr->attrib);
                    fpScr->charset=1;
                    break;

                case 0x0f:      /* CTRL-O found (invoke 'normal' (G0) character set) */
                    if(fpScr->G0)
                        fpScr->attrib=VSgraph(fpScr->attrib);
                    else
                        fpScr->attrib=VSnotgraph(fpScr->attrib);
                    fpScr->charset=0;
                    break;
#endif
#ifdef CISB
                case 0x10:      /* CTRL-P found (undocumented in vt100) */
                    bp_DLE( c, len);
                    len=0;
                    break;
#endif

#ifdef NOT_USED
                case 0x11:      /* CTRL-Q found (XON) (unused presently) */
                case 0x13:      /* CTRL-S found (XOFF) (unused presently) */
                case 0x18:      /* CTRL-X found (CAN) (unused presently) */
                case 0x1a:      /* CTRL-Z found (SUB) (unused presently) */
                    break;
#endif
              } /* end switch */
            c++;        /* advance to the next character in the string */
            len--;      /* decrement the counter */
          } /* end while */

        if(escflg==0) {  /* check for normal character to print */
            while((len>0) && (*c>=32)) {     /* print out printable ascii chars, if we haven't found an ESCAPE char */
                int sx;
                int insert,
                    ocount,
                    attrib,
                    extra,
                    offend;
                char *acurrent,         /* pointer to the attributes for characters drawn */
                    *current,           /* pointer to the place to put characters */
                    *start;

                hgScrLine=GetScreenLineFromY(fpScr,fpScr->y);
                fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
                if (fpScrLine==NULL) return;

                current=start=&fpScrLine->text[fpScr->x];
                acurrent=&fpScrLine->attrib[fpScr->x];
                attrib=fpScr->attrib;
                insert=fpScr->IRM;          /* boolean */
                ocount=fpScr->x;
                offend=0;
                extra=0;
                sx=fpScr->x;
                if(fpScr->x>fpScr->width) {
                    if(fpScr->DECAWM) {  /* check for line wrapping on */
                        fpScr->x=0;
                        ScreenIndex(fpScr);
                      } /* end if */
                    else                /* no line wrapping */
                        fpScr->x=fpScr->width;
                    current=start=&fpScrLine->text[fpScr->x];
                    acurrent=&fpScrLine->attrib[fpScr->x];
                    ocount=fpScr->x;
                    sx=fpScr->x;
                } /* end if */
                while((len>0) && (*c>=32) && (offend==0)) {
                    if(insert)
                        ScreenInsChar(fpScr,1);
                    *current=*c;
                    *acurrent=(char)attrib;
                    c++;
                    len--;
                    if(fpScr->x<fpScr->width) {
                        acurrent++;
                        current++;
                        fpScr->x++;
                      } /* end if */
                    else {
                        if(fpScr->DECAWM) {
                            fpScr->x++;
                            offend=1;
                          } /* end if */
                        else {
                            fpScr->x=fpScr->width;
                            extra=1;
                          } /* end else */
                      } /* end else */
                  } /* end while */
                if (insert)
                    ScreenInsString(fpScr,fpScr->x-ocount+offend+extra,start);        /* actually just decides which RS to use */
                else 
                    ScreenDraw(fpScr,sx,fpScr->y,fpScr->attrib,fpScr->x-ocount+offend+extra,start);
              } /* end while */
          } /* end if */
          
        while((len>0) && (escflg==1)) {     /* ESC character was found */
            switch(*c) {
                case 0x08:      /* CTRL-H found (backspace) */
                    ScreenBackspace(fpScr);
                    break;

                case '[':               /* mostly cursor movement options, and DEC private stuff following */
//                    OutputDebugString("[");
                    ScreenApClear(fpScr);
                    escflg=2;
                    break;

                case '#':               /* various screen adjustments */
//                    OutputDebugString("#");
                    escflg=3;
                    break;

                case '(':               /* G0 character set options */
//                    OutputDebugString("(");
                    escflg=4;
                    break;

                case ')':               /* G1 character set options */
//                    OutputDebugString(")");
                    escflg=5;
                    break;

                case '>':               /* keypad numeric mode (DECKPAM) */
//                    OutputDebugString(">");
                    fpScr->DECPAM=0;
                    escflg=0;
                    break;

                case '=':               /* keypad application mode (DECKPAM) */
//                    OutputDebugString("=");
                    fpScr->DECPAM=1;
                    escflg=0;
                    break;

                case '7':               /* save cursor (DECSC) */
//                    OutputDebugString("7!");
                    ScreenSaveCursor(fpScr);
                    escflg=0;
                    break;

                case '8':               /* restore cursor (DECRC) */
//                    OutputDebugString("8!");
                    ScreenRestoreCursor(fpScr);
                    escflg=0;
                    break;
#ifdef LATER
                case 'c':               /* reset to initial state (RIS) */
                    ScreenReset(fpScr);
                    escflg=0;
                    break;
#endif
                case 'D':               /* index (move down one line) (IND) */
                    ScreenIndex(fpScr);
                    escflg=0;
                    break;

                case 'E':               /*  next line (move down one line and to first column) (NEL) */
//                    OutputDebugString("E!");
                    fpScr->x=0;
                    ScreenIndex(fpScr);
                    escflg=0;
                    break;

                case 'H':               /* horizontal tab set (HTS) */
//                    OutputDebugString("H!");
                    fpScr->tabs[fpScr->x]='x';
                    escflg=0;
                    break;

#ifdef CISB
                case 'I':               /* undoumented in vt100 */
                    bp_ESC_I();
                    break;

#endif

                case 'M':               /* reverse index (move up one line) (RI) */
//                    OutputDebugString("M!");
                    ScreenRevIndex(fpScr);
                    escflg=0;
                    break;

                case 'Z':               /* identify terminal (DECID) */
                    OutputDebugString("Screen Send Ident- Not implemented! \r\n");
//                    ScreenSendIdent(fpScr);

                    escflg=0;
                    break;

                default:
                    ScreenEmChar(fpScr,0x1b); /* put the ESC character into the Screen */
                    ScreenEmChar(fpScr,*c);   /* put the next character into the Screen */
                    escflg=0;
                    break;

              } /* end switch */
            c++;
            len--;
          } /* end while */
        while((escflg==2) && (len>0)) {     /* '[' handling */            
            switch(*c) {
                case 0x08:      /* backspace */
                    ScreenBackspace(fpScr);
                    break;

                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':               /* numeric parameters */
                    if(fpScr->parms[fpScr->parmptr]<0)
                        fpScr->parms[fpScr->parmptr]=0;
                    fpScr->parms[fpScr->parmptr]*=10;
                    fpScr->parms[fpScr->parmptr]+=*c-'0';
                    break;

                case '?':               /* vt100 mode change */
                    fpScr->parms[fpScr->parmptr++]=(-2);
                    break;

                case ';':               /* parameter divider */
                    fpScr->parmptr++;
                    break;

                case 'A':               /* cursor up (CUU) */
//                    OutputDebugString("A");
                    rc.left=((fpScr->x)*(fpScr->cxChar));
                    rc.right=(((fpScr->x)+1)*(fpScr->cxChar));
                    rc.top=((fpScr->cyChar)*(fpScr->y));    
                    rc.bottom=((fpScr->cyChar)*((fpScr->y)+1));
                    InvalidateRect(fpScr->hWnd,&rc,TRUE);
//                    OutputDebugString("[2A]");
                    if(fpScr->parms[0]<1)
                        fpScr->y--;
                    else
                        fpScr->y-=fpScr->parms[0];
                    if(fpScr->y<fpScr->top)
                        fpScr->y=fpScr->top;
                    ScreenRange(fpScr);
                    escflg=0;
                    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
                    break;

                case 'B':               /* cursor down (CUD) */
//                    OutputDebugString("B");
                    rc.left=((fpScr->x)*(fpScr->cxChar));
                    rc.right=(((fpScr->x)+1)*(fpScr->cxChar));
                    rc.top=((fpScr->cyChar)*(fpScr->y));    
                    rc.bottom=((fpScr->cyChar)*((fpScr->y)+1));
                    InvalidateRect(fpScr->hWnd,&rc,TRUE);
//                    OutputDebugString("[2B]");
                    if(fpScr->parms[0]<1)
                        fpScr->y++;
                    else
                        fpScr->y+=fpScr->parms[0];
                    if(fpScr->y>fpScr->bottom)
                        fpScr->y=fpScr->bottom;
                    ScreenRange(fpScr);
                    escflg=0;
                    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
                    break;

                case 'C':               /* cursor forward (right) (CUF) */
//                    OutputDebugString("C");
                    rc.left=((fpScr->x)*(fpScr->cxChar));
                    rc.right=(((fpScr->x)+1)*(fpScr->cxChar));
                    rc.top=((fpScr->cyChar)*(fpScr->y));    
                    rc.bottom=((fpScr->cyChar)*((fpScr->y)+1));
                    InvalidateRect(fpScr->hWnd,&rc,TRUE);
//                    OutputDebugString("[2C]");
                    if(fpScr->parms[0]<1)
                        fpScr->x++;
                    else
                        fpScr->x+=fpScr->parms[0];
                    ScreenRange(fpScr);
                    if(fpScr->x>fpScr->width)
                        fpScr->x=fpScr->width;
                    escflg=0;
                    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
                    break;

                case 'D':               /* cursor backward (left) (CUB) */
//                    OutputDebugString("D");
                    rc.left=((fpScr->x)*(fpScr->cxChar));
                    rc.right=(((fpScr->x)+1)*(fpScr->cxChar));
                    rc.top=((fpScr->cyChar)*(fpScr->y));    
                    rc.bottom=((fpScr->cyChar)*((fpScr->y)+1));
                    InvalidateRect(fpScr->hWnd,&rc,TRUE);
//                    OutputDebugString("[2D]");
                    if(fpScr->parms[0]<1)
                        fpScr->x--;
                    else
                        fpScr->x-=fpScr->parms[0];
                    ScreenRange(fpScr);
                    escflg=0;
                    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
                    break;

                case 'f':               /* horizontal & vertical position (HVP) */
                case 'H':               /* cursor position (CUP) */
//                    OutputDebugString("fH");
                    rc.left=((fpScr->x)*(fpScr->cxChar));
                    rc.right=(((fpScr->x)+1)*(fpScr->cxChar));
                    rc.top=((fpScr->cyChar)*(fpScr->y));    
                    rc.bottom=((fpScr->cyChar)*((fpScr->y)+1));
                    InvalidateRect(fpScr->hWnd,&rc,TRUE);
//                    OutputDebugString("[2H]");
                    fpScr->x=fpScr->parms[1]-1;
                    fpScr->y=fpScr->parms[0]-1;
                    ScreenRange(fpScr);         /* make certain the cursor position is valid */
                    escflg=0;
                    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
                    break;

                case 'J':               /* erase in display (ED) */
//                    OutputDebugString("J");
                    switch(fpScr->parms[0]) {
                        case -1:
                        case 0:     /* erase from active position to end of screen */
                            ScreenEraseToEndOfScreen(fpScr);
                            break;
                        case 1:     /* erase from start of screen to active position */
                            OutputDebugString("[Screen Erase to Position- Not Implemented!]\r\n");
//                            ScreenEraseToPosition(fpScr);
                            break;

                        case 2:     /* erase whole screen */
//                            OutputDebugString("2");
                            ScreenEraseScreen(fpScr);
                            break;

                        default:
                            break;
                      } /* end switch */
                    escflg=0;
                    break;

                case 'K':               /* erase in line (EL) */
//                    OutputDebugString("K");
                    switch(fpScr->parms[0]) {
                        case -1:
                        case 0:     /* erase to end of line */
//                            OutputDebugString("0");
                            ScreenEraseToEOL(fpScr);
                            break;

                        case 1:     /* erase to beginning of line */
//                            OutputDebugString("1");
                            ScreenEraseToBOL(fpScr);
                            break;

                        case 2:     /* erase whole line */
//                            OutputDebugString("2");
                            ScreenEraseLine(fpScr,-1);
                            break;

                        default:
                            break;
                      } /* end switch */
                    escflg=0;
                    break;

                case 'L':               /* insert n lines preceding current line (IL) */
//                    OutputDebugString("L");
                    if(fpScr->parms[0]<1)
                        fpScr->parms[0]=1;
                    ScreenInsLines(fpScr,fpScr->parms[0],-1);
                    escflg=0;
                    break;

                case 'M':               /* delete n lines from current position downward (DL) */
//                    OutputDebugString("M");
                    if(fpScr->parms[0]<1)
                        fpScr->parms[0]=1;
                    ScreenDelLines(fpScr,fpScr->parms[0],-1);
                    escflg=0;
                    break;

                case 'P':               /* delete n chars from cursor to the left (DCH) */
//                    OutputDebugString("P");
                    if(fpScr->parms[0]<1)
                        fpScr->parms[0]=1;
                    ScreenDelChars(fpScr,fpScr->parms[0]);
                    escflg=0;
                    break;

#ifdef NOT_NEEDED
                case 'R':               /* receive cursor position status from host */
                    break;
#endif
#ifdef LATER
                case 'c':               /* device attributes (DA) */
                    ScreenSendIdent();
                    escflg=0;
                    break;
#endif
                case 'g':               /* tabulation clear (TBC) */
//                    OutputDebugString("g");
                    if(fpScr->parms[0]==3)   /* clear all tabs */
                        ScreenTabClear(fpScr);
                    else
                        if(fpScr->parms[0]<=0)   /* clear tab stop at active position */
                            fpScr->tabs[fpScr->x]=' ';
                    escflg=0;
                    break;

                case 'h':               /* set mode (SM) */
//                    OutputDebugString("h");
//                  ScreenSetOption(fpScr,1);
                    escflg=0;
                    break;


                case 'i':               /* toggle printer */
//                    if(fpScr->parms[fpScr->parmptr]==5)
//                        fpScr->localprint=1;
//                    else if(fpScr->parms[fpScr->parmptr]==4)
//                        fpScr->localprint=0;
                    escflg=0;
                    break;

                case 'l':               /* reset mode (RM) */
//                    OutputDebugString("l");
//                    ScreenSetOption(fpScr,0);
                    escflg=0;
                    break;

                case 'm':               /* select graphics rendition (SGR) */
//                    OutputDebugString("m");
                    {
                        int temp=0;

                        while(temp<=fpScr->parmptr) {
                            if(fpScr->parms[temp]<1)
                                fpScr->attrib&=128;
                            else
                                fpScr->attrib|=(1<<(fpScr->parms[temp]-1));
                            temp++;
                          } /* end while */
                      } /* end case */
                    escflg=0;
                    break;

                case 'n':               /* device status report (DSR) */
                    switch(fpScr->parms[0]) {
#ifdef NOT_SUPPORTED
                    case 0: /* response from vt100; ready, no malfunctions */
                    case 3: /* response from vt100; malfunction, retry */
#endif
                    case 5: /* send status */
                    case 6: /* send active position */
						wsprintf(stat, "\033[%d;%dR", fpScr->y, fpScr->x);
						for (i = 0; stat[i]; i++)
							SendMessage(fpScr->hwndTel,WM_MYSCREENCHAR,stat[i],hsScr);
                        break;
                    } /* end switch */
                    escflg=0;
                    break;

                case 'q':               /* load LEDs (unsupported) (DECLL) */
                    escflg=0;
                    break;

                case 'r':               /* set top & bottom margins (DECSTBM) */
                    if(fpScr->parms[0]<0)
                        fpScr->top=0;
                    else
                        fpScr->top=fpScr->parms[0]-1;
                    if(fpScr->parms[1]<0)
                        fpScr->bottom=fpScr->height-1;
                    else
                        fpScr->bottom=fpScr->parms[1]-1;
                    if(fpScr->top<0)
                        fpScr->top=0;
                    if(fpScr->top>fpScr->height-1)
                        fpScr->top=fpScr->height-1;
                    if(fpScr->bottom<1)
                        fpScr->bottom=fpScr->height;
                    if(fpScr->bottom>=fpScr->height)
                        fpScr->bottom=fpScr->height-1;
                    if(fpScr->top>=fpScr->bottom) {   /* check for valid scrolling region */
                        if(fpScr->bottom>=1)     /* assume the bottom value has precedence, unless it is as the top of the screen */
                            fpScr->top=fpScr->bottom-1;
                        else                /* totally psychotic case, bottom of screen set to the very top line, move the bottom to below the top */
                            fpScr->bottom=fpScr->top+1;
                      } /* end if */
                    fpScr->x=0;
                    fpScr->y=0;
#ifdef NOT_SUPPORTED
                    if (fpScr->DECORG)
                        fpScr->y=fpScr->top;  /* origin mode relative */
#endif
                    escflg=0;
                    break;

#ifdef NOT_SUPPORTED
                case 'x':                       /* request/report terminal parameters (DECREQTPARM/DECREPTPARM) */
                case 'y':                       /* invoke confidence test (DECTST) */
                    break;
#endif
                default:            /* Dag blasted strays... */
                    escflg=0;
                    break;

              } /* end switch */
            c++;
            len--;

#ifdef NOT
/* @UM */
            if(fpScr->localprint && (len>0)) {    /* see if printer needs anything */
                pcount=send_localprint(c,len);
                len-=pcount;
                c+=pcount;
              } /* end if */
/* @UM */
#endif
          } /* end while */
        while((escflg==3) && (len>0)) { /* #  Handling */
            switch(*c) {
                case 0x08:      /* backspace */
                    ScreenBackspace(fpScr);
                    break;

#ifdef NOT_SUPPORTED
                case '3':               /* top half of double line (DECDHL) */
                case '4':               /* bottom half of double line (DECDHL) */
                case '5':               /* single width line (DECSWL) */
                case '6':               /* double width line (DECDWL) */
                    break;
#endif
                case '8':               /* screen alignment display (DECALN) */
                    ScreenAlign(fpScr);
//                    OutputDebugString("8");
                    escflg=0;
                    break;
                default:
                    escflg=0;
                    break;

              } /* end switch */
            c++;
            len--;
          } /* end while */
        while((escflg==4) && (len>0)) { /* ( Handling (GO character set) */
            switch(*c) {
                case 0x08:      /* backspace */
                    ScreenBackspace(fpScr);
                    break;

#ifdef LATER
                case 'A':               /* united kingdom character set (unsupported) */
                case 'B':               /* ASCII character set */
                case '1':               /* choose standard graphics (same as ASCII) */
                    fpScr->G0=0;
                    if(!fpScr->charset)
                        fpScr->attrib=ScreenNotGraph(fpScr->attrib);
                    escflg=0;
                    break;

                case '0':               /* choose special graphics set */
                case '2':               /* alternate character set (special graphics) */
                    fpScr->G0=1;
                    if(!fpScr->charset)
                        fpScr->attrib=ScreenGraph(fpScr->attrib);
                    escflg=0;
                    break;
#endif
                default:
                    escflg=0;
                    break;
              } /* end switch */
            c++;
            len--;
          } /* end while */
        while((escflg==5) && (len>0)) { /* ) Handling (G1 handling) */
            switch(*c) {
                case 0x08:      /* backspace */
                    ScreenBackspace(fpScr);
                    break;

#ifdef LATER
                case 'A':               /* united kingdom character set (unsupported) */
                case 'B':               /* ASCII character set */
                case '1':               /* choose standard graphics (same as ASCII) */
                    fpScr->G1=0;
                    if(fpScr->charset)
                        fpScr->attrib=ScreenNotGraph(fpScr->attrib);
                    escflg=0;
                    break;

                case '0':               /* choose special graphics set */
                case '2':               /* alternate character set (special graphics) */
                    fpScr->G1=1;
                    if(fpScr->charset)
                        fpScr->attrib=ScreenGraph(fpScr->attrib);
                    escflg=0;
                    break;
#endif
                default:
                    escflg=0;
                    break;
              } /* end switch */
            c++;
            len--;
          } /* end while */

        while((escflg>=6) && (escflg<=10) && (len>0)) { /* Handling IAC */
			ic = (unsigned char) *c;
			switch (escflg) {

			case 6:     /* Handling IAC xx */
				if (ic == 255) /* if IAC */
					escflg=0;
                else if (ic == 250) /* if SB */
					escflg=7;
				else
					escflg=9;
				break;

			case 7:     /* Handling IAC SB xx */
				if (ic == 255) /* if IAC */
                    escflg=8;
				break;

			case 8:     /* Handling IAC SB IAC xx */
				if (ic == 255) /* if IAC IAC */
                   escflg=7;
				else if (ic == 240) /* if IAC SE */
                   escflg=0;
				break;

			case 9:    /* IAC xx xx */
				escflg=0;
				break;
			}
            c++;        /* advance to the next character in the string */
            len--;      /* decrement the counter */
		}

        if((escflg>2 && escflg<6) && (len>0)) {
            escflg=0;
            c++;
            len--;
          } /* end if */
      } /* end while */
    fpScr->escflg=escflg;
    ScreenCursorOn(fpScr);
    GlobalUnlock(hsScr);
}   /* end ScreenEm() */
