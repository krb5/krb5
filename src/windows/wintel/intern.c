#include <windows.h>
#include <string.h>
#include "screen.h"
#define ScreenClearAttrib 0

HSCREENLINE GetScreenLineFromY(SCREEN *fpScr,int y)
{
    HSCREENLINE hgScrLine,hgScrLineTmp;
    SCREENLINE *fpScrLine;
    int idx;

    hgScrLine=fpScr->screen_top;
    for (idx=0; idx<fpScr->height; idx++) {
        if (idx==y) return(hgScrLine);
        fpScrLine=LINE_MEM_LOCK(hgScrLine);
        if (fpScrLine==NULL) return (NULL);    
        hgScrLineTmp=fpScrLine->next;        
        LINE_MEM_UNLOCK(hgScrLine);
        hgScrLine=hgScrLineTmp;
    }
    return(NULL);
}    

HSCREENLINE ScreenClearLine(SCREEN *fpScr,HSCREENLINE hgScrLine)
{
    SCREENLINE *fpScrLine;
      
    fpScrLine=LINE_MEM_LOCK(hgScrLine);
	memset(fpScrLine->attrib, ScreenClearAttrib, fpScr->width);
	memset(fpScrLine->text, ' ', fpScr->width);
    LINE_MEM_UNLOCK(hgScrLine);
    return(hgScrLine);
}

void ScreenUnscroll(SCREEN *fpScr)
{
	int idx;
    HSCREENLINE hgScrLine,hgScrLineTmp;
    SCREENLINE *fpScrLine;

    if (fpScr->screen_bottom == fpScr->buffer_bottom)
		return;

    fpScr->screen_bottom=fpScr->buffer_bottom;
    hgScrLine=fpScr->screen_bottom;
    for (idx = 1; idx < fpScr->height; idx++) {
        fpScrLine=LINE_MEM_LOCK(hgScrLine);
        if (fpScrLine==NULL)
            return;
        hgScrLineTmp=fpScrLine->prev;
        LINE_MEM_UNLOCK(hgScrLine);
        hgScrLine=hgScrLineTmp;
    }
    fpScr->screen_top=hgScrLine;
}

void ScreenCursorOn(SCREEN *fpScr)
{
	int y;
	int nlines;

	if (fpScr->screen_bottom != fpScr->buffer_bottom)
    	nlines = fpScr->numlines - GetScrollPos(fpScr->hWnd, SB_VERT);
	else
		nlines = 0;

	y = fpScr->y + nlines;
	SetCaretPos(fpScr->x * fpScr->cxChar, (y+1) * fpScr->cyChar);
	ShowCaret(fpScr->hWnd);
}

void ScreenCursorOff(SCREEN *fpScr)
{
	HideCaret(fpScr->hWnd);
}

void ScreenELO(SCREEN *fpScr,int s)
{
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    RECT rc;
            
/*  fpScrrapnow(&i,&j); */
    if(s<0) 
        s=fpScr->y;
    
    hgScrLine=GetScreenLineFromY(fpScr,s);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
	memset(fpScrLine->attrib, ScreenClearAttrib, fpScr->width);
	memset(fpScrLine->text, ' ', fpScr->width);
    LINE_MEM_UNLOCK(hgScrLine);
    rc.left=0;
    rc.right=(fpScr->width*fpScr->cxChar);
    rc.top=(fpScr->cyChar*s);    
    rc.bottom=(fpScr->cyChar*(s+1));
    InvalidateRect(fpScr->hWnd,&rc,TRUE);
}

void ScreenEraseScreen(SCREEN *fpScr) 
{
    int i;
    int x1=0,y1=0;
    int x2=fpScr->width,y2=fpScr->height;
    int n=(-1);
            
    for(i=0; i<fpScr->height; i++)
        ScreenELO(fpScr,i);
    InvalidateRect(fpScr->hWnd,NULL,TRUE);
    UpdateWindow(fpScr->hWnd);
}

void ScreenTabClear(SCREEN *fpScr)
{
    int x=0;

    while(x<=fpScr->width) {
        fpScr->tabs[x]=' ';
        x++;
      } /* end while */
}

void ScreenTabInit(SCREEN *fpScr)
{
    int x=0;

    ScreenTabClear(fpScr);

    while(x<=fpScr->width) { 
        fpScr->tabs[x]='x';
        x+=8;
    } /* end while */
    fpScr->tabs[fpScr->width]='x';
}

void ScreenReset(SCREEN *fpScr)
{
    fpScr->top=0;
    fpScr->bottom=fpScr->height-1;
    fpScr->parmptr=0;
    fpScr->escflg=0;
    fpScr->DECAWM=1;
    fpScr->DECCKM=0;
    fpScr->DECPAM=0;
/*  fpScr->DECORG=0;     */
/*  fpScr->Pattrib=-1;   */
    fpScr->IRM=0;
    fpScr->attrib=0;
    fpScr->x=0;
    fpScr->y=0;
//    fpScr->charset=0;
    ScreenEraseScreen(fpScr);
    ScreenTabInit(fpScr);
//    set_vtwrap(fpScrn,fpScr->DECAWM);     /* QAK - 7/27/90: added because resetting the virtual screen's wrapping flag doesn't reset telnet window's wrapping */
}


void ScreenListMove(HSCREENLINE hTD,HSCREENLINE hBD,HSCREENLINE hTI,HSCREENLINE hBI)
{
    HSCREENLINE hTmpLine;
    SCREENLINE *TD,*BD,*TI,*BI,*tmpLine;
    
//    OutputDebugString("ScreenListMove");
    TD= (SCREENLINE *)GlobalLock(hTD);
    BD= (SCREENLINE *)GlobalLock(hBD);
    TI= (SCREENLINE *)GlobalLock(hTI);
    BI= (SCREENLINE *)GlobalLock(hBI);
    
    if(TD->prev!=NULL) {
        hTmpLine=TD->prev;
        tmpLine=(SCREENLINE *)GlobalLock(hTmpLine);
        tmpLine->next=BD->next;    /* Maintain circularity */
        GlobalUnlock(hTmpLine);
    }        
    if(BD->next!=NULL) {
        hTmpLine=BD->next;
        tmpLine=(SCREENLINE *)GlobalLock(hTmpLine);
        tmpLine->prev=TD->prev;
        GlobalUnlock(hTmpLine);
    }
    TD->prev=hTI;                    /* Place the node in its new home */
    BD->next=hBI;
    if(TI!=NULL) 
        TI->next=hTD;                /* Ditto prev->prev */
    if(BI!=NULL) 
        BI->prev=hBD;
        
    GlobalUnlock(hTD);
    GlobalUnlock(hBD);
    GlobalUnlock(hTI);
    GlobalUnlock(hBI);            
}


void ScreenDelLines(SCREEN *fpScr, int n, int s)
{
    HSCREENLINE hBI,hTI,hTD,hBD;
    SCREENLINE *TI;
    SCREENLINE *BD;
    HSCREENLINE hLine;
    SCREENLINE *fpLine;
    HSCREENLINE hTemp;
	int idx;
	RECT rc;
	HDC hDC;
    
    if (s < 0) 
        s = fpScr->y;

    if (s + n - 1 > fpScr->bottom)
        n = fpScr->bottom - s + 1;

    hTD = GetScreenLineFromY(fpScr, s);
    hBD = GetScreenLineFromY(fpScr, s + n - 1);
    hTI = GetScreenLineFromY(fpScr, fpScr->bottom);
    TI= LINE_MEM_LOCK(hTI);
    hBI = TI->next;
    LINE_MEM_UNLOCK(hTI);

	/*
	Adjust the top of the screen and buffer if they will move.
	*/
	if (hTD == fpScr->screen_top) {
	    BD = LINE_MEM_LOCK(hBD);
		if (fpScr->screen_top == fpScr->buffer_top)
			fpScr->buffer_top = BD->next;
		fpScr->screen_top = BD->next;
	    LINE_MEM_UNLOCK(hBD);
	}

	/*
	Adjust the bottom of the screen and buffer if they will move.
	*/
	if (hTI == fpScr->screen_bottom) {
		if (fpScr->screen_bottom == fpScr->buffer_bottom)
			fpScr->buffer_bottom = hBD;
		fpScr->screen_bottom = hBD;
	}

    if (hTI != hBD)
        ScreenListMove(hTD, hBD, hTI, hBI);

	/*
	Clear the lines moved from the deleted area to the
	bottom of the scrolling area.
	*/
	hLine = hTI;

	for (idx = 0; idx < n; idx++) {
		fpLine = LINE_MEM_LOCK(hLine);
		hTemp = fpLine->next;
		LINE_MEM_UNLOCK(hLine);
		hLine = hTemp;
		ScreenClearLine(fpScr, hLine);
	}

//	CheckScreen(fpScr);

	/*
	Scroll the affected area on the screen.
	*/
    rc.left = 0;
    rc.right = fpScr->width * fpScr->cxChar;
    rc.top = s * fpScr->cyChar;
    rc.bottom = (fpScr->bottom + 1) * fpScr->cyChar;

    hDC = GetDC(fpScr->hWnd);

    ScrollDC(hDC, 0, -fpScr->cyChar * n, &rc, &rc, NULL, NULL);

    PatBlt(hDC, 0, (fpScr->bottom - n + 1) * fpScr->cyChar,
		fpScr->width * fpScr->cxChar, n * fpScr->cyChar, WHITENESS);

    ReleaseDC(fpScr->hWnd, hDC);

} /* ScreenDelLines */


void ScreenInsertLine(SCREEN *fpScr, int s)
{
	ScreenInsLines(fpScr, 1, s);
} /* ScreenInsertLine */


void ScreenInsLines(SCREEN *fpScr, int n, int s)
{
    HSCREENLINE hLine;
    HSCREENLINE hTemp;
    HSCREENLINE hTI;
    HSCREENLINE hBI;
    HSCREENLINE hTD;
    HSCREENLINE hBD;
    SCREENLINE *fpLine;
    SCREENLINE *BI;
	SCREENLINE *TD;
    int idx;
    RECT rc;
    HDC hDC;
 
//    wsprintf(strTmp, "ScreenInsLine (n=%d s=%d)", n, s);
//    OutputDebugString(strTmp);

    if (s < 0)
		s = fpScr->y;

    if (s + n - 1 > fpScr->bottom) 
        n = fpScr->bottom - s + 1;

	/*
	Determine the top and bottom of the insert area.  Also determine
	the top and bottom of the area to be deleted and moved to the
	insert area.
	*/
    hBI = GetScreenLineFromY(fpScr, s);
    BI = LINE_MEM_LOCK(hBI);
    hTI = BI->prev;
    hTD = GetScreenLineFromY(fpScr, fpScr->bottom - n + 1);
    hBD = GetScreenLineFromY(fpScr, fpScr->bottom);
    
	/*
	Adjust the top of the screen and buffer if they will move.
	*/
	if (hBI == fpScr->screen_top) {
		if (fpScr->screen_top == fpScr->buffer_top)
			fpScr->buffer_top = hTD;
		fpScr->screen_top = hTD;
	}

	/*
	Adjust the bottom of the screen and buffer if they will move.
	*/
	if (hBD == fpScr->screen_bottom) {
	    TD = LINE_MEM_LOCK(hTD);
		if (fpScr->screen_bottom == fpScr->buffer_bottom)
			fpScr->buffer_bottom = TD->prev;
		fpScr->screen_bottom = TD->prev;
	    LINE_MEM_UNLOCK(hTD);
	}

	/*
	Move lines from the bottom of the scrolling region to the insert area.
	*/
    if (hTD != hBI)
        ScreenListMove(hTD,hBD,hTI,hBI);

	/*
	Clear the inserted lines
	*/
    hLine = GetScreenLineFromY(fpScr, s);

    for (idx = 0; idx < n; idx++) {
		ScreenClearLine(fpScr, hLine);
        fpLine = LINE_MEM_LOCK(hLine);
		hTemp = fpLine->next;
        LINE_MEM_UNLOCK(hLine);
		hLine = hTemp;
    }

//	CheckScreen(fpScr);

	/*
	Scroll the affected area on the screen.
	*/
    rc.left = 0;
    rc.right = fpScr->width * fpScr->cxChar;
    rc.top = s * fpScr->cyChar;
    rc.bottom = (fpScr->bottom + 1) * fpScr->cyChar;

    hDC = GetDC(fpScr->hWnd);

    ScrollDC(hDC, 0, fpScr->cyChar * n, &rc, &rc, NULL, NULL);

    PatBlt(hDC, 0, s * fpScr->cyChar,
		fpScr->width * fpScr->cxChar, n * fpScr->cyChar, WHITENESS);

    ReleaseDC(fpScr->hWnd, hDC);

} /* ScreenInsLines */


void ScreenIndex(SCREEN * fpScr)
{
    if(fpScr->y>=fpScr->bottom)
        ScreenScroll(fpScr);
    else
        fpScr->y++;    
}

void ScreenWrapNow(SCREEN *fpScr,int *xp,int *yp)
{
    if(fpScr->x > fpScr->width) {
        fpScr->x=0;
        ScreenIndex(fpScr);
      } /* end if */
    *xp=fpScr->x;
    *yp=fpScr->y;
}

void ScreenEraseToEOL(SCREEN *fpScr)
{
    int x1=fpScr->x,y1=fpScr->y;
    int x2=fpScr->width,y2=fpScr->y;
    int n=(-1);
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    RECT rc;
        
    ScreenWrapNow(fpScr,&x1,&y1);
    y2=y1;
//    wsprintf(strTmp,"[EraseEOL:%d]",y2);
//    OutputDebugString(strTmp);
    hgScrLine=GetScreenLineFromY(fpScr,y2);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
	memset(&fpScrLine->attrib[x1], ScreenClearAttrib, fpScr->width-x1+1);
	memset(&fpScrLine->text[x1], ' ', fpScr->width-x1+1);
    LINE_MEM_UNLOCK(hgScrLine);      
    rc.left=x1*fpScr->cxChar;
    rc.right=(fpScr->width*fpScr->cxChar);
    rc.top=(fpScr->cyChar*y1);    
    rc.bottom=(fpScr->cyChar*(y1+1));
    InvalidateRect(fpScr->hWnd,&rc,TRUE);
    UpdateWindow(fpScr->hWnd);
}

void ScreenDelChars(SCREEN *fpScr, int n)
{
    int x = fpScr->x;
	int y = fpScr->y;
    int width;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    RECT rc;
	
    hgScrLine = GetScreenLineFromY(fpScr, y);
    fpScrLine = LINE_MEM_LOCK(hgScrLine);

	width = fpScr->width - x - n;

	if (width > 0) {
		memmove(&fpScrLine->attrib[x], &fpScrLine->attrib[x + n], width);
		memmove(&fpScrLine->text[x], &fpScrLine->text[x + n], width);
	}

	memset(&fpScrLine->attrib[fpScr->width - n], ScreenClearAttrib, n);
    memset(&fpScrLine->text[fpScr->width - n], ' ', n);
	
    LINE_MEM_UNLOCK(hgScrLine);

    rc.left = x * fpScr->cxChar;
    rc.right = fpScr->width * fpScr->cxChar;
    rc.top = fpScr->cyChar * y;
    rc.bottom = fpScr->cyChar * (y + 1);

    InvalidateRect(fpScr->hWnd, &rc, TRUE);

    UpdateWindow(fpScr->hWnd);
}

void ScreenRevIndex(SCREEN *fpScr)
{
    HSCREENLINE hgScrLine,hTopLine;
    
    hgScrLine=GetScreenLineFromY(fpScr,fpScr->y);
    hTopLine=GetScreenLineFromY(fpScr,fpScr->top);
    
    if(hgScrLine==hTopLine) 
        ScreenInsertLine(fpScr,fpScr->y);
    else
        fpScr->y--;
}

void ScreenEraseToBOL(SCREEN *fpScr)
{
    int x1=0,y1=fpScr->y;
    int x2=fpScr->x,y2=fpScr->y;
    int n=(-1);
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;

    hgScrLine=GetScreenLineFromY(fpScr,fpScr->y);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);

    ScreenWrapNow(fpScr,&x2,&y1);
    y2=y1;
	memset(fpScrLine->attrib, ScreenClearAttrib, x2);
	memset(fpScrLine->text, ' ', x2);
    LINE_MEM_UNLOCK(hgScrLine);      
}

void ScreenEraseLine(SCREEN *fpScr,int s)
{
    int x1=0,y1=s;
    int x2=fpScr->width,y2=s;
    int n=(-1);
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    RECT rc;
    
    if(s<0) {
        ScreenWrapNow(fpScr,&x1,&y1);
        s=y2=y1;
        x1=0;
      } /* end if */

    hgScrLine=GetScreenLineFromY(fpScr,y1);
    fpScrLine=LINE_MEM_LOCK(hgScrLine);
	memset(fpScrLine->attrib, ScreenClearAttrib, fpScr->width);
	memset(fpScrLine->text, ' ', fpScr->width);
    LINE_MEM_UNLOCK(hgScrLine);      
    rc.left=0;
    rc.right=(fpScr->width*fpScr->cxChar);
    rc.top=(fpScr->cyChar*y1);    
    rc.bottom=(fpScr->cyChar*(y1+1));
    InvalidateRect(fpScr->hWnd,&rc,TRUE);
    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
}

void ScreenEraseToEndOfScreen(SCREEN *fpScr)
{
    register int i;
    int x1=0,y1=fpScr->y+1;
    int x2=fpScr->width,y2=fpScr->height;
    int n=(-1);

    ScreenWrapNow(fpScr,&x1,&y1);
    y1++;
    x1=0;
    i=y1;
    ScreenEraseToEOL(fpScr);
    while(i<fpScr->height) {
        ScreenELO(fpScr,i);
        ScreenEraseLine(fpScr,i);
        i++;
    } /* end while */
}

void ScreenRange(SCREEN *fpScr)               /* check and resolve range errors on x and y */
{
    int wrap=0;

    if(fpScr->DECAWM)
        wrap=1;
    if(fpScr->x<0)
        fpScr->x=0;
    if(fpScr->x>(fpScr->width+wrap))
        fpScr->x=fpScr->width+wrap;
    if(fpScr->y<0)
        fpScr->y=0;
    if(fpScr->y>=fpScr->height)
        fpScr->y=fpScr->height-1;
}

void ScreenAlign(SCREEN *fpScr)  /* vt100 alignment, fill screen with 'E's */
{
    char *tt;
    register int i,j;
    HSCREENLINE hgScrLine,hgScrLineTmp;
    SCREENLINE *fpScrLine;
    
    hgScrLine=GetScreenLineFromY(fpScr,fpScr->top);
    ScreenEraseScreen(fpScr);        /* erase the screen */

    for(j=0; j<fpScr->height; j++) {
        fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
        tt=&fpScrLine->text[0];
        for(i=0; i<=fpScr->width; i++)
            *tt++='E';
        hgScrLineTmp=fpScrLine->next;            
        LINE_MEM_UNLOCK(hgScrLine);
        hgScrLine=hgScrLineTmp;    
        
      } /* end for */
    LINE_MEM_UNLOCK(hgScrLine);      
}

/* reset all the ANSI parameters back to the default state */
void ScreenApClear(SCREEN *fpScr)
{
    for(fpScr->parmptr=5; fpScr->parmptr>=0; fpScr->parmptr--)
        fpScr->parms[fpScr->parmptr]=-1;
    fpScr->parmptr=0;
}

void ScreenSetOption(SCREEN *fpScr,int toggle) {
//    int WindWidth=(fpScr->width - 1);

    switch(fpScr->parms[0]) {
        case -2:
            switch(fpScr->parms[1]) {
                case 1:     /* set/reset cursor key mode */
                    fpScr->DECCKM=toggle;
                    break;

#ifdef NOT_SUPPORTED
                case 2:     /* set/reset ANSI/vt52 mode */
                    break;
#endif

                case 3:     /* set/reset column mode */
                    fpScr->x=fpScr->y=0;      /* Clear the screen, mama! */
                    ScreenEraseScreen(fpScr);
					#if 0	/* removed for variable screen size */
	                    if(toggle)      /* 132 column mode */
    	                    fpScr->width=fpScr->allwidth;
        	            else
            	            fpScr->width=79;
					#endif
                    break;

#ifdef NOT_SUPPORTED
                case 4:     /* set/reset scrolling mode */
                case 5:     /* set/reset screen mode */
                case 6:     /* set/rest origin mode */
                    fpScr->DECORG = toggle;
                    break;
#endif

                case 7:     /* set/reset wrap mode */
                    fpScr->DECAWM=toggle;
//                    set_vtwrap(fpScrn,fpScr->DECAWM);     /* QAK - 7/27/90: added because resetting the virtual screen's wrapping flag doesn't reset telnet window's wrapping */
                    break;

#ifdef NOT_SUPPORTED
                case 8:     /* set/reset autorepeat mode */
                case 9:     /* set/reset interlace mode */
                    break;
#endif

                default:
                    break;
            } /* end switch */
            break;

        case 4:
            fpScr->IRM=toggle;
            break;

        default:
            break;

    } /* end switch */
}

#ifdef NOT_SUPPORTED
void ScreenTab(SCREEN *fpScr)
{
    if(fpScr->x>=fpScr->width)
        fpScr->x=fpScr->width;
    fpScr->x++;
    while((fpScr->tabs[fpScr->x] != 'x') && (fpScr->x < fpScr->width)) 
        fpScr->x++;
}
#endif

int ScreenInsChar(SCREEN *fpScr,int x)
{
    int i;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    RECT rc;
        
//    ScreenWrapNow(&i,&j);  /* JEM- Why is this here? comment out for now */

//    OutputDebugString("OOPS-InsChar!");
    hgScrLine=GetScreenLineFromY(fpScr,fpScr->y);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
    if (fpScrLine==NULL) return (-1);

    for(i=fpScr->width-x; i>=fpScr->x; i--) {
        fpScrLine->text[x+i]=fpScrLine->text[i];
        fpScrLine->attrib[x+i]=fpScrLine->attrib[i];
    } /* end for */

	memset(&fpScrLine->attrib[fpScr->x], ScreenClearAttrib, x);
	memset(&fpScrLine->text[fpScr->x], ' ', x);

    for(i=fpScr->x; i<fpScr->x+x; i++) {
        fpScrLine->text[i]=' ';
        fpScrLine->attrib[i]=ScreenClearAttrib;
    } /* end for */
    LINE_MEM_UNLOCK(hgScrLine);  
    rc.left= (fpScr->cxChar*x);
    rc.right= ((fpScr->cxChar*x)+(fpScr->cxChar*(x+fpScr->x)));
    rc.top=(fpScr->cyChar*((fpScr->y)-1));    
    rc.bottom=(fpScr->cyChar*(fpScr->y));
    InvalidateRect(fpScr->hWnd,&rc,TRUE);
    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
}

void ScreenInsString(SCREEN *fpScr,int len,char *start)
{
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    int idx;
    RECT rc;
    
    if(fpScr->VSIDC) return;  /* Call RSinsstring which does nothing? */
    
    hgScrLine=GetScreenLineFromY(fpScr,fpScr->y);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
    if (fpScrLine==NULL) return;

    for(idx=fpScr->x; idx<fpScr->x+len; idx++) {
        fpScrLine->text[idx]=start[idx];
        fpScrLine->attrib[idx]=fpScr->attrib;
    } /* end for */
    LINE_MEM_UNLOCK(hgScrLine);
    rc.left= (fpScr->cxChar*fpScr->x);
    rc.right= ((fpScr->cxChar*fpScr->x)+(fpScr->cxChar*(fpScr->x+len)));
    rc.top=(fpScr->cyChar*(fpScr->y));    
    rc.bottom=(fpScr->cyChar*(fpScr->y+1));    
    
    InvalidateRect(fpScr->hWnd,&rc,TRUE);
    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
}

void ScreenSaveCursor(SCREEN *fpScr)
{
    fpScr->Px=fpScr->x;
    fpScr->Py=fpScr->y;
    fpScr->Pattrib=fpScr->attrib;
}

void ScreenRestoreCursor(SCREEN *fpScr)
{
    fpScr->x=fpScr->Px;
    fpScr->y=fpScr->Py;
    ScreenRange(fpScr);
}

void ScreenDraw(SCREEN *fpScr,int x,int y,int a,int len,char *c)
{
	int idx;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    RECT rc;

    hgScrLine=GetScreenLineFromY(fpScr,y);  
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
    if (fpScrLine==NULL) {
        OutputDebugString("fpScrLine==NULL");
        return;
    }
    
    for(idx=x; idx<(x+len); idx++) {
        fpScrLine->text[idx]=c[idx-x];
        fpScrLine->attrib[idx-x]=a;
    } 
    LINE_MEM_UNLOCK(hgScrLine);

	rc.left= (fpScr->cxChar*x);
    rc.right= (fpScr->cxChar*(x+len));
	rc.top=(fpScr->cyChar*(fpScr->y));    
    rc.bottom=(fpScr->cyChar*((fpScr->y)+1));
	InvalidateRect(fpScr->hWnd,&rc,TRUE);    
    SendMessage(fpScr->hWnd,WM_PAINT,NULL,NULL);
}

#ifdef _DEBUG

	BOOL CheckScreen(SCREEN *fpScr)
	{
		HSCREENLINE hLine;
		HSCREENLINE hLinePrev;
		SCREENLINE *fpLine;
		int nscreen = 0;
		int nbuffer = 0;
		int topline = 0;
		char buf[512];
		BOOL bBottom;
		BOOL bOK;

		hLine = fpScr->buffer_top;

		if (hLine == NULL) {
			OutputDebugString("CheckScreen: buffer_top invalid");
			MessageBox(NULL, "buffer_top invalid", "CheckScreen", MB_OK);
			return(FALSE);
		}

		bBottom = FALSE;
		while (TRUE) {
			hLinePrev = hLine;
			if (nscreen > 0 || hLine == fpScr->screen_top)
				if (!bBottom)
					nscreen++;
			nbuffer++;
			if (hLine == fpScr->screen_top)
				topline = nbuffer - 1;
			if (hLine == fpScr->screen_bottom)
				bBottom = TRUE;
			fpLine = LINE_MEM_LOCK(hLine);
			hLine = fpLine->next;
			LINE_MEM_UNLOCK(hLine);
			if (hLine == NULL)
				break;
			fpLine = LINE_MEM_LOCK(hLine);
			if (fpLine->prev != hLinePrev) {
				wsprintf(buf,
					"Previous ptr of line %d does not match next ptr of line %d",
					nbuffer, nbuffer - 1);
				OutputDebugString(buf);
				MessageBox(NULL, buf, "CheckScreen", MB_OK);
			}
			LINE_MEM_UNLOCK(hLine);
		}

		if (hLinePrev == fpScr->buffer_bottom && nscreen == fpScr->height)
			bOK = TRUE;
		else {
			OutputDebugString("CheckScreen: Invalid number of lines on screen");
			bOK = FALSE;
		}

		wsprintf(buf, \
			"screen.width = %d\n"
			"screen.height = %d\n"
			"screen.maxlines = %d\n"
			"screen.numlines = %d\n"
			"screen.x = %d\n"
			"screen.y = %d\n"
			"screen.top = %d\n"
			"screen.bottom = %d\n"
			"Actual top line = %d\n"
			"Actual buffer lines = %d\n"
			"Actual screen lines = %d\n"
			"Bottom of buffer is %s",
			fpScr->width, fpScr->height, fpScr->maxlines, fpScr->numlines,
			fpScr->x, fpScr->y, fpScr->top, fpScr->bottom,
			topline, nbuffer, nscreen,
			(hLinePrev == fpScr->buffer_bottom) ? "valid" : "invalid");

		MessageBox(NULL, buf, "CheckScreen", MB_OK);

		return(bOK);
	}

#endif
