#include <windows.h>
#include <commdlg.h>
#include <stdlib.h>
#include <string.h>
#include "telnet.h"
#include "ini.h"

extern char *cInvertedArray;
HSCREEN ScreenList;
HINSTANCE hInst;
HDC hDC;
char gszAllocErrorMsg[]="Error Allocating Memory!";
char gszLockErrorMsg[]="Error Locking Memory!";
char gszLoadStrFail[]="LoadString failed!";

int bDoubleClick=FALSE;
extern LOGFONT lf;
extern HFONT hFont;
extern int bMouseDown;
extern int bSelection;

char szScreenClass[]="ScreenWClass";
char szScreenMenu[]="ScreenMenu";

OFSTRUCT ofFile;
HFILE fh;

#ifdef WINMEM
CATCHBUF EndRtn;              /* error return buffer (required by WinMem)*/
#endif

//#define FILE_DEBUG

void ScreenInit(HANDLE hInstance) {

    WNDCLASS    wc;

    hInst=hInstance;
    
//    wsprintf(strTmp,"hInst= %d \r\n",hInst);
//    OutputDebugString(strTmp);
    
    ScreenList=NULL;

    wc.style = CS_HREDRAW|CS_VREDRAW|CS_DBLCLKS|CS_GLOBALCLASS;       /* Class style(s).                    */
    wc.lpfnWndProc = ScreenWndProc;         /* Function to retrieve messages for  */
                                            /* windows of this class.             */
    wc.cbClsExtra = 0;                      /* No per-class extra data.           */
    wc.cbWndExtra = sizeof(HGLOBAL);        /* Only extra data is handle to screen*/
    wc.hInstance = hInstance;               /* Application that owns the class.   */
    wc.hIcon = LoadIcon(hInstance, "TERMINAL");
    wc.hCursor = LoadCursor(NULL, IDC_IBEAM);
    wc.hbrBackground = GetStockObject(WHITE_BRUSH);
    wc.lpszMenuName =  szScreenMenu;        /* Name of menu resource in .RC file. */
    wc.lpszClassName = szScreenClass;      /* Name used in call to CreateWindow. */

    /* Register the window class and return success/failure code. */
    if (!RegisterClass(&wc))
    	MessageBox(NULL,"Couldn't register Class!",NULL,MB_OK);
}

int GetNewScreen(void) {
    HGLOBAL ghScr;
    SCREEN *fpScr, *fpTmp, *fpTmp2;
    static int id=0;

    if (ScreenList==NULL) {
        ghScr = GlobalAlloc(GHND,sizeof(SCREEN));
        if (ghScr==NULL) return -1;
        fpScr = (SCREEN *)GlobalLock(ghScr);
        if (fpScr==NULL) return -1;
        fpScr->next=NULL;
        fpScr->prev=NULL;
        GlobalUnlock(ghScr);
        ScreenList=ghScr;
        return(id++);
    }
	else {
        ghScr = GlobalAlloc(GHND,sizeof(SCREEN));
        if (ghScr==NULL) return -1;
        fpScr = (SCREEN *)GlobalLock(ghScr);
        if (fpScr==NULL) return -1;
        fpScr->next=ScreenList;
        fpTmp = (SCREEN *)GlobalLock(ScreenList);
		if (fpTmp != NULL) {
            if (fpTmp->next==NULL) {
                fpScr->next=ScreenList;
                fpScr->prev=ScreenList;
                fpTmp->next=ghScr;
                fpTmp->prev=ghScr;
            } else {
                fpScr->prev=fpTmp->prev;
	            fpTmp2 = (SCREEN *)GlobalLock(fpTmp->prev);
			    if (fpTmp2 != NULL)
	    	        fpTmp2->next=ghScr;
                GlobalUnlock(fpTmp->prev);
	            fpTmp->prev=ghScr;
            }
        }
        GlobalUnlock(fpScr->next);
        GlobalUnlock(ghScr);
        ScreenList=ghScr;
        return(id++);
    }
}

HSCREENLINE ScreenNewLine(void) 
{

    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;

    hgScrLine=LINE_MEM_ALLOC(sizeof(SCREENLINE)+2*MAX_LINE_WIDTH);
    if (hgScrLine==NULL)
		return (NULL);
    fpScrLine=LINE_MEM_LOCK(hgScrLine);
    if (fpScrLine==NULL)
		return (NULL);
	memset(fpScrLine,0,sizeof(SCREENLINE)+2*MAX_LINE_WIDTH);
	fpScrLine->text=&fpScrLine->buffer[0];
	fpScrLine->attrib=&fpScrLine->buffer[MAX_LINE_WIDTH];
    LINE_MEM_UNLOCK(hgScrLine);
    return(hgScrLine);
}  

static void MakeWindowTitle(char *host, int width, int height, char *title, int nchars)
{
	char buf[128];
	int hlen;

	hlen = strlen(host);

	title[0] = 0;

	if (hlen + 1 > nchars)
		return;

	strcpy(title, host);

	wsprintf(buf, " (%dh x %dw)", height, width);

	if ((int) strlen(buf) + hlen + 1 > nchars)
		return;

	strcat(title, buf);
}

HSCREEN InitNewScreen(CONFIG *Config) {
    TEXTMETRIC  tm;
    HMENU hMenu=NULL;
    SCREEN *scr=NULL;
    HSCREENLINE hgScrLine;
    HSCREENLINE hgScrLineLast;
    SCREENLINE *fpScrLine;
    SCREENLINE *fpScrLineLast;
    int id,idx=0;
	HGLOBAL h;
	char title[128];

    id=GetNewScreen();
    if (id == -1) return(0);
    scr=(SCREEN *) GlobalLock(ScreenList);
    if (scr==NULL) OutputDebugString("Scr is NULL!\r\n");
	        
    hMenu = LoadMenu(hInst,szScreenMenu);
    if (hMenu==NULL) OutputDebugString("hMenu is NULL! \r\n");
    
	scr->title=Config->title;
	MakeWindowTitle(Config->title,Config->width,Config->height,title,sizeof(title));

    scr->hWnd = CreateWindow((char *)szScreenClass,title,WS_OVERLAPPEDWINDOW|WS_VSCROLL,
        CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,NULL,hMenu,hInst,NULL);
    
	if (!(scr->hWnd)) {
		OutputDebugString("Couldn't Create Window!! \r\n");
		return(0); 
	}
    scr->hwndTel=Config->hwndTel;  /* save HWND of calling window */
	
	if (Config->backspace) {
        CheckMenuItem(hMenu,IDM_BACKSPACE,MF_CHECKED);
        CheckMenuItem(hMenu,IDM_DELETE,MF_UNCHECKED);
    }
	else {
        CheckMenuItem(hMenu,IDM_BACKSPACE,MF_UNCHECKED);
        CheckMenuItem(hMenu,IDM_DELETE,MF_CHECKED);
    }    
    SetWindowWord(scr->hWnd,SCREEN_HANDLE,(WORD)ScreenList);
    hDC = GetDC(scr->hWnd);

    scr->lf.lfPitchAndFamily=FIXED_PITCH;
    GetPrivateProfileString(INI_FONT,"FaceName","Courier",scr->lf.lfFaceName,
        LF_FACESIZE,TELNET_INI);
    scr->lf.lfHeight=(int)GetPrivateProfileInt(INI_FONT,"Height",0,TELNET_INI);
    scr->lf.lfWidth=(int)GetPrivateProfileInt(INI_FONT,"Width",0,TELNET_INI);
    scr->lf.lfPitchAndFamily=(BYTE)GetPrivateProfileInt(INI_FONT,"PitchAndFamily",0,TELNET_INI);
    scr->lf.lfCharSet=(BYTE)GetPrivateProfileInt(INI_FONT,"CharSet",0,TELNET_INI);
    scr->lf.lfEscapement=(BYTE)GetPrivateProfileInt(INI_FONT,"Escapement",0,TELNET_INI);
    scr->lf.lfQuality=PROOF_QUALITY;
    scr->ghSelectedFont = CreateFontIndirect((LPLOGFONT)&(scr->lf));
    
    SelectObject(hDC,scr->ghSelectedFont);
                
    GetTextMetrics(hDC,(LPTEXTMETRIC)&tm);
    scr->cxChar = tm.tmAveCharWidth;
    scr->cyChar = tm.tmHeight + tm.tmExternalLeading;

    ReleaseDC(scr->hWnd,hDC);
    scr->width=Config->width;
    scr->height=Config->height;
    scr->ID=id;
    scr->x=0;    
    scr->y=0;
    scr->Oldx=0;
    scr->Oldy=0;
    scr->attrib=0;
    scr->DECAWM=1;
    scr->top=0;
    scr->bottom=scr->height-1;
    scr->parmptr=0;
    scr->escflg=0;
    scr->bAlert=FALSE;
    scr->numlines=0;
    scr->maxlines=150;

	h=GlobalAlloc(GHND,scr->width*scr->height);
	if (h==NULL)
		return(0);
	cInvertedArray=GlobalLock(h);

    hgScrLineLast=ScreenNewLine();
    scr->screen_top=scr->buffer_top=hgScrLineLast;
	hgScrLine=hgScrLineLast;

    for (idx=0; idx<scr->height-1; idx++) {
        hgScrLine=ScreenNewLine();
        fpScrLine=LINE_MEM_LOCK(hgScrLine);
		if (fpScrLine == NULL)
			return(NULL);
        fpScrLine->prev=hgScrLineLast;
        LINE_MEM_UNLOCK(hgScrLine);

        fpScrLineLast=LINE_MEM_LOCK(hgScrLineLast);
		if (fpScrLineLast == NULL)
			return(NULL);
        fpScrLineLast->next=hgScrLine;
        LINE_MEM_UNLOCK(hgScrLineLast);

        hgScrLineLast=hgScrLine;
    }

    scr->screen_bottom=scr->buffer_bottom=hgScrLine;

    SetWindowPos(scr->hWnd,NULL,0,0,scr->cxChar * scr->width + FRAME_WIDTH,
         scr->cyChar * scr->height + FRAME_HEIGHT, SWP_NOMOVE|SWP_NOZORDER);

	CreateCaret(scr->hWnd, NULL, scr->cxChar, 2);
	SetCaretPos(scr->x*scr->cxChar, (scr->y+1)*scr->cyChar);
	ShowCaret(scr->hWnd);

    GlobalUnlock(ScreenList);
    return(ScreenList);
}

void DeleteTopLine(SCREEN *fpScr) {
    HSCREENLINE hsTop;
    SCREENLINE *fpScrLine;
    
    fpScrLine=(SCREENLINE *) LINE_MEM_LOCK(fpScr->buffer_top);
    if (fpScrLine==NULL) OutputDebugString("Hosed in DeleteTopLine.\r\n");
    hsTop=fpScrLine->next;
    LINE_MEM_FREE(fpScr->buffer_top);
    fpScr->buffer_top=hsTop;
    fpScrLine=(SCREENLINE *) LINE_MEM_LOCK(fpScr->buffer_top);
    if (fpScrLine==NULL) OutputDebugString("Hosed in DeleteTopLine.\r\n");
    fpScrLine->prev=NULL;
    LINE_MEM_UNLOCK(fpScr->buffer_top);
    fpScr->numlines--;
}


static void SetScreenScrollBar(SCREEN *fpScr)
{
	if (fpScr->numlines <= 0) {
		SetScrollRange(fpScr->hWnd, SB_VERT, 0, 100, FALSE);
		SetScrollPos(fpScr->hWnd, SB_VERT, 0, TRUE);
		EnableScrollBar(fpScr->hWnd, SB_VERT, ESB_DISABLE_BOTH);
	}
	else {
		SetScrollRange(fpScr->hWnd, SB_VERT, 0, fpScr->numlines, FALSE);
		SetScrollPos(fpScr->hWnd, SB_VERT, fpScr->numlines, TRUE);
		EnableScrollBar(fpScr->hWnd, SB_VERT, ESB_ENABLE_BOTH);
	}
} /* SetScreenScrollBar */


int ScreenScroll(SCREEN *fpScr)
{
    HSCREENLINE hgScrLine;
    HSCREENLINE hScrollTop;
    HSCREENLINE hScrollBottom;
    HSCREENLINE hPrev;
    HSCREENLINE hNext;
    SCREENLINE *fpScrLine;
    SCREENLINE *fpPrev;
    SCREENLINE *fpNext;
    SCREENLINE *fpScrollTop;
    SCREENLINE *fpScrollBottom;
    BOOL bFullScreen = TRUE;
    HDC hDC;
    RECT rc;

    Edit_ClearSelection(fpScr);

    hScrollTop = (HSCREENLINE) GetScreenLineFromY(fpScr, fpScr->top);

    hScrollBottom = (HSCREENLINE) GetScreenLineFromY(fpScr, fpScr->bottom);

    if (hScrollTop != fpScr->screen_top) {
		bFullScreen = FALSE;
        rc.left = 0;
        rc.right = fpScr->cxChar * fpScr->width;
        rc.top = fpScr->cyChar * (fpScr->top);
        rc.bottom = fpScr->cyChar * (fpScr->bottom+1);

	    fpScrollTop = LINE_MEM_LOCK(hScrollTop);
        hNext = fpScrollTop->next;
        hPrev = fpScrollTop->prev;
		LINE_MEM_UNLOCK(hScrollTop);

        fpPrev = LINE_MEM_LOCK(hPrev);
        fpPrev->next = hNext;        
        fpNext = LINE_MEM_LOCK(hNext);
        fpNext->prev = hPrev;
        LINE_MEM_UNLOCK(hPrev);
		LINE_MEM_UNLOCK(hNext);

		hgScrLine = hScrollTop;
		ScreenClearLine(fpScr, hgScrLine);
    }
	else {
		fpScr->numlines++;                
		hgScrLine = ScreenNewLine(); 
		if (hgScrLine == NULL)
			return(0);
		fpScrollTop = LINE_MEM_LOCK(hScrollTop);
		fpScr->screen_top = fpScrollTop->next;
		LINE_MEM_UNLOCK(hScrollTop);
    }    

    fpScrLine= LINE_MEM_LOCK(hgScrLine);
    if (fpScrLine == NULL)
		return(0);

	fpScrollBottom = LINE_MEM_LOCK(hScrollBottom);
    hNext = fpScrollBottom->next;
	fpScrollBottom->next = hgScrLine;
	LINE_MEM_UNLOCK(hScrollBottom);
	fpScrLine->next = hNext;
	fpScrLine->prev = hScrollBottom;
	if (hNext != NULL) {
	    fpNext = LINE_MEM_LOCK(hNext);
	    fpNext->prev = hgScrLine;
		LINE_MEM_UNLOCK(hNext);
	}

	LINE_MEM_UNLOCK(hgScrLine);

    if (hScrollBottom != fpScr->screen_bottom) {
		bFullScreen = FALSE;
        rc.left = 0;
        rc.right = fpScr->cxChar * fpScr->width;
        rc.top = fpScr->cyChar * fpScr->top;
        rc.bottom = fpScr->cyChar * (fpScr->bottom+1);
    }
	else {
		if (fpScr->screen_bottom == fpScr->buffer_bottom)
			fpScr->buffer_bottom = hgScrLine;
		fpScr->screen_bottom = hgScrLine;
	}

//	CheckScreen(fpScr);

	fpScr->y++;

	if (fpScr->y > fpScr->bottom)
		fpScr->y = fpScr->bottom;

	hDC = GetDC(fpScr->hWnd);
	if (bFullScreen)
		ScrollDC(hDC, 0, -fpScr->cyChar, NULL, NULL, NULL, NULL);
	else 
		ScrollDC(hDC, 0, -fpScr->cyChar, &rc, &rc, NULL, NULL);

	PatBlt(hDC, 0, fpScr->bottom * fpScr->cyChar,
		fpScr->width * fpScr->cxChar, fpScr->cyChar, WHITENESS);
        
	ReleaseDC(fpScr->hWnd, hDC);

	if (fpScr->numlines == fpScr->maxlines)
		DeleteTopLine(fpScr);
	else
		SetScreenScrollBar(fpScr);

	return(1);
}


void DrawCursor(SCREEN *fpScr) {
#ifdef NOT
    HDC hDC;
    char ch=95;

    hDC=GetDC(fpScr->hWnd);
    SelectObject(hDC,fpScr->ghSelectedFont);
    SetTextColor(hDC,RGB(255,255,255));
    TextOut(hDC,fpScr->Oldx*fpScr->cxChar,fpScr->Oldy*fpScr->cyChar,&ch,1);
    fpScr->Oldx=fpScr->x;
    fpScr->Oldy=fpScr->y;
    SetTextColor(hDC,RGB(0,0,0));
    TextOut(hDC,fpScr->x*fpScr->cxChar,fpScr->y*fpScr->cyChar,&ch,1);
    ReleaseDC(fpScr->hWnd,hDC);                
#endif    
}

int DrawTextScreen(RECT rcInvalid, SCREEN * fpScr, HDC hDC)
{
	HSCREENLINE hgScrLine, hgScrLineTmp;
	SCREENLINE *fpScrLine;
	int x=0, y=0;
	int left=0, right=0;
	int i;
	int len;
	char attrib;
	#define YPOS (y*fpScr->cyChar)

    hgScrLine=fpScr->screen_top;
//    hgScrLine=GetScreenLineFromY(fpScr,0);
//    wsprintf(strTmp,"{DTS: (%d)=%X }",fpScr->top,hgScrLine);
//    OutputDebugString(strTmp);

	for (y = 0; y < fpScr->height; y++) {
		fpScrLine = LINE_MEM_LOCK(hgScrLine);

		if (!fpScrLine)
			continue;

		if (YPOS >= rcInvalid.top - fpScr->cyChar && 
			YPOS <= rcInvalid.bottom + fpScr->cyChar) {

			if (y < 0)
				y = 0;

			if (y >= fpScr->height)
				y = fpScr->height - 1;

			left = (rcInvalid.left / fpScr->cxChar) - 1;

			right = (rcInvalid.right / fpScr->cxChar) + 1;

			if (left < 0)
				left = 0;

			if (right > fpScr->width - 1)
				right = fpScr->width - 1;

			x = left;

			while (x <= right) {
				if (!fpScrLine->text[x]) {
					x++;
					continue;
				}

				if (SCR_isrev(fpScrLine->attrib[x])) {
					SelectObject(hDC, fpScr->ghSelectedFont);                
					SetTextColor(hDC, RGB(255, 255, 255));
					SetBkColor(hDC, RGB(0, 0, 0));
				}
				else if (SCR_isblnk(fpScrLine->attrib[x])) {
					SelectObject(hDC, fpScr->ghSelectedFont);                
					SetTextColor(hDC, RGB(255, 0, 0));
					SetBkColor(hDC, RGB(255, 255, 255));
				}
				else if (SCR_isundl(fpScrLine->attrib[x])) {
					SetTextColor(hDC, RGB(255, 0, 0));
					SetBkColor(hDC, RGB(255, 255, 255));
					SelectObject(hDC, fpScr->ghSelectedULFont);
				}
				else {
					SelectObject(hDC,fpScr->ghSelectedFont);
					SetTextColor(hDC,RGB(0, 0, 0));
					SetBkColor(hDC,RGB(255, 255, 255));
				}

				len = 1;
				attrib = fpScrLine->attrib[x];
				for (i = x + 1; i <= right; i++) {
					if (fpScrLine->attrib[i] != attrib || !fpScrLine->text[i])
						break;
					len++;
				}

				TextOut(hDC, x*fpScr->cxChar, y*fpScr->cyChar, &fpScrLine->text[x], len);
				x += len;
			}
		}                
		hgScrLineTmp = fpScrLine->next;
		LINE_MEM_UNLOCK(hgScrLine);
		hgScrLine = hgScrLineTmp;
	}            
	return(0);
}

static BOOL SetInternalScreenSize(SCREEN *fpScr, int width, int height)
{
	RECT rc;
	char *p;
	HGLOBAL h;
	int idx;
	int n;
	int newlines;
	HSCREENLINE hgNewLine;
	SCREENLINE *fpNewLine;
	HSCREENLINE hgTopLine;
	SCREENLINE *fpTopLine;
	HSCREENLINE hgBottomLine;
	SCREENLINE *fpBottomLine;
	#if 0
		int col;
		int row;
		int dydestbottom;
	#endif

	GetClientRect(fpScr->hWnd, &rc);

	width = (rc.right - rc.left) / fpScr->cxChar;
	height = (rc.bottom - rc.top) / fpScr->cyChar;

	if (fpScr->height == height && fpScr->width == width)
		return(FALSE);

    fpScr->Oldx = 0;
    fpScr->Oldy = 0;
    fpScr->attrib = 0;

	/*
	Reallocate the inverted array of bytes and copy the values
	from the old screen to the new screen.
	*/
	h = GlobalAlloc(GHND, width * height);
	if (h == NULL)
		return(0);

	ScreenCursorOff(fpScr);

	p = GlobalLock(h);

	#if 0	/* Copy inversion array to desitination */
		for (col = 0; col < width; col++) {
			for (row = 0; row < height; row++) {
				dydestbottom = height - 1 - row;
				if (col < fpScr->width && dydestbottom < fpScr->height - 1)
					p[row * width + col] =
						cInvertedArray[(fpScr->height - 1 - dydestbottom) * fpScr->width + col];
			}
		}
	#endif

	h = LOWORD(GlobalHandle(SELECTOROF(cInvertedArray)));
	GlobalUnlock(h);
	GlobalFree(h);
	cInvertedArray = p;

	/*
	Append any new lines which need to be added to accomodate the new
	screen size.
	*/
	hgBottomLine = fpScr->buffer_bottom;
	newlines = height - (fpScr->height + fpScr->numlines);

	if (newlines > 0) {
		fpScr->y += fpScr->numlines;
		fpScr->numlines = 0;

    	for (idx = 0; idx < newlines; idx++) {
        	hgNewLine = ScreenNewLine();
        	fpNewLine = LINE_MEM_LOCK(hgNewLine);
			if (fpNewLine == NULL)
				return(FALSE);
        	fpNewLine->prev = hgBottomLine;

			fpBottomLine = LINE_MEM_LOCK(hgBottomLine);
			if (fpBottomLine == NULL)
				return(FALSE);
			fpBottomLine->next = hgNewLine;
			LINE_MEM_UNLOCK(hgBottomLine);

			LINE_MEM_UNLOCK(hgNewLine);

			hgBottomLine = hgNewLine;
    	}
	}

	/*
	If we already have plenty of lines, then we need to get rid of the
	scrollback lines, if too many exist.  The cursor should end up
	the same distance from the bottom of the screen as is started out
	in this instance.
	*/
	if (newlines < 0) {
		fpScr->y = (height - 1) - (fpScr->bottom - fpScr->y);
		if (fpScr->y < 0)
			fpScr->y = 0;
		fpScr->numlines = -newlines;
		n = fpScr->numlines - fpScr->maxlines;
		for (idx = 0; idx < n; idx++)
			DeleteTopLine(fpScr);
	}
		
	/*
	Calculate the position of the buffer relative to the screen.
	*/
    fpScr->screen_bottom = hgBottomLine;
	fpScr->buffer_bottom = hgBottomLine;

	hgTopLine = hgBottomLine;

	for (idx = 1; idx < height; idx++) {
		fpTopLine = LINE_MEM_LOCK(hgTopLine);
		hgTopLine = fpTopLine->prev;
		LINE_MEM_UNLOCK(hgTopLine);
	}

	fpScr->screen_top = hgTopLine;
    fpScr->width = width;
    fpScr->height = height;
    fpScr->top = 0;
    fpScr->bottom = height - 1;

	if (fpScr->x >= width)
		fpScr->x = width - 1;

	if (fpScr->y >= height)
		fpScr->y = height - 1;

	SetScreenScrollBar(fpScr);
	ScreenCursorOn(fpScr);
	return(TRUE);
}

static int ScreenAdjustUp(SCREEN *fpScr, int n)
{
	int idx;
	HSCREENLINE hslLine1;
	HSCREENLINE hslLine2;
	SCREENLINE *fpScrLine1;
	SCREENLINE *fpScrLine2;

	for (idx = 0; idx < n; idx++) {
	    if (fpScr->screen_top == fpScr->buffer_top)
			return(-idx);
	   	fpScrLine1 = LINE_MEM_LOCK(fpScr->screen_top);
    	hslLine1 = fpScrLine1->prev;
    	LINE_MEM_UNLOCK(fpScr->screen_top);
    	if (hslLine1 == NULL)
			return(-idx);
    	fpScrLine2 = LINE_MEM_LOCK(fpScr->screen_bottom);
    	hslLine2 = fpScrLine2->prev;
    	LINE_MEM_UNLOCK(fpScr->screen_bottom);
    	if (hslLine2 == NULL)
			return(-idx);
    	fpScr->screen_top = hslLine1;
    	fpScr->screen_bottom = hslLine2;                    
	}
	return(idx);
}

static int ScreenAdjustDown(SCREEN *fpScr, int n)
{
	int idx;
	HSCREENLINE hslLine1;
	HSCREENLINE hslLine2;
	SCREENLINE *fpScrLine1;
	SCREENLINE *fpScrLine2;

	for (idx = 0; idx < n; idx++) {
    	if (fpScr->screen_bottom == fpScr->buffer_bottom)
			return(-idx);
    	fpScrLine1 = LINE_MEM_LOCK(fpScr->screen_top);
    	hslLine1 = fpScrLine1->next;
    	LINE_MEM_UNLOCK(fpScr->screen_top);
    	if (hslLine1 == NULL)
			return(-idx);
    	fpScrLine2 = LINE_MEM_LOCK(fpScr->screen_bottom);
    	hslLine2 = fpScrLine2->next;
    	LINE_MEM_UNLOCK(fpScr->screen_bottom);
    	if (hslLine2 == NULL)
			return(-idx);
    	fpScr->screen_top = hslLine1;
    	fpScr->screen_bottom = hslLine2;
	}
	return(idx);
}

long FAR PASCAL ScreenWndProc(hWnd, message, wParam, lParam)
HWND hWnd;                /* window handle           */
UINT message;                 /* type of message         */
WPARAM wParam;                  /* additional information          */
LPARAM lParam;                  /* additional information          */
{
	MINMAXINFO *lpmmi;
    SCREEN *fpScr;                              
    HGLOBAL hgScr;
    HMENU hMenu;
    PAINTSTRUCT ps;    
    int x=0,
        y=0,
        ScrollPos,tmpScroll=0,
        idx;
    HSCREENLINE hslLine;
	HDC hDC;
	RECT rc;
	char title[128];
         
    switch (message) {

    case WM_COMMAND:
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
	    fpScr=(SCREEN *)GlobalLock(hgScr);
	    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");

        switch (wParam) {               

        case IDM_BACKSPACE:
            hMenu=GetMenu(hWnd);
            CheckMenuItem(hMenu,IDM_BACKSPACE,MF_CHECKED);
            CheckMenuItem(hMenu,IDM_DELETE,MF_UNCHECKED);
            SendMessage(fpScr->hwndTel,WM_MYSCREENCHANGEBKSP,VK_BACK,(HSCREEN)hgScr);                                
            break;
        case IDM_DELETE:
            hMenu=GetMenu(hWnd);
            CheckMenuItem(hMenu,IDM_BACKSPACE,MF_UNCHECKED);
            CheckMenuItem(hMenu,IDM_DELETE,MF_CHECKED);
            SendMessage(fpScr->hwndTel,WM_MYSCREENCHANGEBKSP,0x7f,(HSCREEN)hgScr);                                
            break;    
        case IDM_FONT:
			ScreenCursorOff(fpScr);
            ProcessFontChange(hWnd);
			ScreenCursorOn(fpScr);
            break;
        case IDM_COPY:
            Edit_Copy(hWnd);
            hMenu=GetMenu(hWnd);
            Edit_ClearSelection(fpScr);                
            GlobalUnlock(hgScr);
            break;
        case IDM_PASTE:
            Edit_Paste(hWnd);
            break;
    	case IDM_ABOUT:
	        #ifdef KRB4
        		strcpy(strTmp, "        Kerberos 4 for Windows\n");
            #endif
            #ifdef KRB5
                strcpy(strTmp, "        Kerberos 5 for Windows\n");
            #endif
            strcat(strTmp, "\n                Version 1.00\n\n");
            strcat(strTmp, "          For support, contact:\n");
            strcat(strTmp, "Cygnus Support");
            strcat(strTmp, " - (415) 903-1400");
            MessageBox(NULL, strTmp, "Kerberos", MB_OK);
            break;
#ifdef _DEBUG
		case IDM_DEBUG:
			CheckScreen(fpScr);
			break;
#endif
        }        

		GlobalUnlock(hgScr);
        break;

    case WM_CREATE:
//        OutputDebugString("WM_CREATE\r\n");
        SetWindowWord(hWnd,SCREEN_HANDLE,NULL);
        SetScrollRange(hWnd,SB_VERT,0,100,FALSE);
		SetScrollPos(hWnd,SB_VERT,0,TRUE);
		EnableScrollBar(hWnd,SB_VERT,ESB_DISABLE_BOTH);
        ShowWindow(hWnd,SW_SHOW);
#ifdef FILE_DEBUG
        fh=OpenFile("d:\\debug.txt",&ofFile,OF_CREATE|OF_WRITE);
#endif
        break;
        
    case WM_VSCROLL:
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
        fpScr=(SCREEN *)GlobalLock(hgScr);
        if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");

		ScreenCursorOff(fpScr);

        switch(wParam) {
        case SB_LINEDOWN:
			if (ScreenAdjustDown(fpScr, 1) <= 0)
				break;
			hDC = GetDC(hWnd);
			rc.left = 0;
			rc.right = fpScr->cxChar * fpScr->width;
			rc.top = 0;
			rc.bottom = fpScr->cyChar * (fpScr->bottom+1);
			ScrollDC(hDC, 0, -fpScr->cyChar, &rc, &rc, NULL, NULL);
			ReleaseDC(hWnd, hDC);
			rc.top = fpScr->cyChar * fpScr->bottom;
			InvalidateRect(hWnd, &rc, TRUE);
            ScrollPos=GetScrollPos(hWnd,SB_VERT);
            SetScrollPos(hWnd,SB_VERT,ScrollPos+1,TRUE);
			UpdateWindow(hWnd);
            break;

        case SB_LINEUP:
			if (ScreenAdjustUp(fpScr, 1) <= 0)
				break;
			hDC = GetDC(hWnd);
			rc.left = 0;
			rc.right = fpScr->cxChar * fpScr->width;
			rc.top = 0;
			rc.bottom = fpScr->cyChar * (fpScr->bottom+1);
			ScrollDC(hDC, 0, fpScr->cyChar, &rc, &rc, NULL, NULL);
			ReleaseDC(hWnd, hDC);
			rc.bottom = fpScr->cyChar;
			InvalidateRect(hWnd, &rc, TRUE);
            ScrollPos=GetScrollPos(fpScr->hWnd,SB_VERT);
            SetScrollPos(hWnd,SB_VERT,ScrollPos-1,TRUE);
			UpdateWindow(hWnd);
            break;

        case SB_PAGEDOWN:
			idx = abs(ScreenAdjustDown(fpScr, fpScr->height));
			hDC = GetDC(hWnd);
			rc.left = 0;
			rc.right = fpScr->cxChar * fpScr->width;
			rc.top = 0;
			rc.bottom = fpScr->cyChar * (fpScr->bottom+1);
			ScrollDC(hDC, 0, -idx * fpScr->cyChar, &rc, &rc, NULL, NULL);
			ReleaseDC(hWnd, hDC);
			rc.top = fpScr->cyChar * (fpScr->bottom - idx + 1);
			InvalidateRect(hWnd, &rc, TRUE);
            ScrollPos=GetScrollPos(hWnd,SB_VERT);
            SetScrollPos(hWnd,SB_VERT,ScrollPos+idx,TRUE);
            break;

        case SB_PAGEUP:
			idx = abs(ScreenAdjustUp(fpScr, fpScr->height));
			hDC = GetDC(hWnd);
			rc.left = 0;
			rc.right = fpScr->cxChar * fpScr->width;
			rc.top = 0;
			rc.bottom = fpScr->cyChar * (fpScr->bottom+1);
			ScrollDC(hDC, 0, idx * fpScr->cyChar, &rc, &rc, NULL, NULL);
			ReleaseDC(hWnd, hDC);
			rc.bottom = idx * fpScr->cyChar;
			InvalidateRect(hWnd, &rc, TRUE);
            ScrollPos=GetScrollPos(hWnd,SB_VERT);
            SetScrollPos(hWnd,SB_VERT,ScrollPos-idx,TRUE);
            break;

        case SB_THUMBPOSITION:
        case SB_THUMBTRACK:
            ScrollPos = GetScrollPos(hWnd,SB_VERT);
            tmpScroll = ScrollPos - LOWORD(lParam);
			if (tmpScroll == 0)
				break;
			if (tmpScroll > 0)
				ScreenAdjustUp(fpScr, tmpScroll);
			else
				ScreenAdjustDown(fpScr, -tmpScroll);
			if (abs(tmpScroll) < fpScr->height) {
				hDC=GetDC(hWnd);
				rc.left = 0;
				rc.right = fpScr->cxChar * fpScr->width;
				rc.top = 0;
				rc.bottom = fpScr->cyChar * (fpScr->bottom+1);
				ScrollDC(hDC,0,tmpScroll*fpScr->cyChar,&rc,&rc,NULL,NULL);
				ReleaseDC(hWnd, hDC);
				if (tmpScroll > 0) {
					rc.bottom = tmpScroll * fpScr->cyChar;
					InvalidateRect(hWnd, &rc, TRUE);
				}
				else {
					rc.top = (fpScr->bottom + tmpScroll + 1) * fpScr->cyChar;
					InvalidateRect(hWnd, &rc, TRUE);
				}
			}
			else
				InvalidateRect(hWnd, NULL, TRUE);

            SetScrollPos(hWnd,SB_VERT,LOWORD(lParam),TRUE);
			UpdateWindow(hWnd);
            break;
        }
		ScreenCursorOn(fpScr);
        GlobalUnlock(hgScr);
        break;
    
    case WM_KEYDOWN:
        if (wParam==VK_INSERT) {
            if (GetKeyState(VK_SHIFT)<0) 
                PostMessage(hWnd,WM_COMMAND,IDM_PASTE,NULL);
            else if (GetKeyState(VK_CONTROL)<0)
                PostMessage(hWnd,WM_COMMAND,IDM_COPY,NULL);
            break;
        }        
        if ((wParam < VK_PRIOR)||(wParam > VK_DOWN)) break;
        switch (wParam) {
        case VK_PRIOR:	/* Page up   */
            SendMessage(hWnd,WM_VSCROLL,SB_PAGEUP,NULL);               
            break;
        case VK_NEXT:	/* Page down */
            SendMessage(hWnd,WM_VSCROLL,SB_PAGEDOWN,NULL);
            break;
        case VK_UP:		/* Line up   */
            SendMessage(hWnd,WM_VSCROLL,SB_LINEUP,NULL);
            break;
        case VK_DOWN:	/* Line down */
            SendMessage(hWnd,WM_VSCROLL,SB_LINEDOWN,NULL);
            break;
        }
        UpdateWindow(hWnd);
        break;
        
    case WM_CHAR:
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) {
        	OutputDebugString("Hosed #1.\r\n");
        	break;
        }	
        fpScr=(SCREEN *)GlobalLock(hgScr);
        if (fpScr == NULL) {
        	OutputDebugString("Hosed #2.\r\n");
        	break;
        }	
        SendMessage(fpScr->hwndTel,WM_MYSCREENCHAR,wParam,(HSCREEN)hgScr);
        GlobalUnlock(hgScr);
        break;

    case WM_SYSCHAR:
        if ((wParam=='c')||(wParam=='e'))
            return (DefWindowProc(hWnd, message, wParam, lParam));
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) {
        	OutputDebugString("Hosed #1.\r\n");
        	break;
        }	
        fpScr=(SCREEN *)GlobalLock(hgScr);
        if (fpScr == NULL) {
        	OutputDebugString("Hosed #2.\r\n");
        	break;
        }
        SendMessage(fpScr->hwndTel,WM_MYSYSCHAR,wParam,(HSCREEN)hgScr);
        GlobalUnlock(hgScr);
        break;

    case WM_INITMENU:
        if (IsClipboardFormatAvailable(CF_TEXT))
            EnableMenuItem((HMENU) wParam,IDM_PASTE,MF_ENABLED);
        else EnableMenuItem((HMENU) wParam,IDM_PASTE,MF_GRAYED);
        if (bSelection) EnableMenuItem((HMENU) wParam,IDM_COPY,MF_ENABLED);
        else EnableMenuItem((HMENU) wParam,IDM_COPY,MF_GRAYED);
        break;
                              
    case WM_GETMINMAXINFO:
//        OutputDebugString("WM_GETMINMAX_INFO\r\n");
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) break;
        fpScr=(SCREEN *)GlobalLock(hgScr);
//        if (fpScr == NULL) OutputDebugString("Hosed in GetMinMaxInfo.\r\n");
//        wsprintf(strTmp,"cx=%d cy=%d width=%d height=%d",fpScr->cxChar,fpScr->cyChar,fpScr->width,fpScr->height);
//        OutputDebugString(strTmp);
	    lpmmi = (MINMAXINFO *) lParam;
		if (FRAME_WIDTH + MAX_LINE_WIDTH * fpScr->cxChar < lpmmi->ptMaxSize.x)
			lpmmi->ptMaxSize.x = FRAME_WIDTH + MAX_LINE_WIDTH * fpScr->cxChar;
		lpmmi->ptMaxTrackSize.x = lpmmi->ptMaxSize.x;
		lpmmi->ptMinTrackSize.x = FRAME_WIDTH + 20 * fpScr->cxChar;
		lpmmi->ptMinTrackSize.y = FRAME_HEIGHT + 4 * fpScr->cyChar;
	    GlobalUnlock(hgScr);
        break;
    
    case WM_LBUTTONDOWN: 
        if (bDoubleClick) Edit_TripleClick(hWnd,lParam);
        else Edit_LbuttonDown(hWnd,lParam);
        break;
    
    case WM_LBUTTONUP:
        Edit_LbuttonUp(hWnd,lParam);
        break;

    case WM_LBUTTONDBLCLK:
        bDoubleClick=TRUE;
        SetTimer(hWnd,TIMER_TRIPLECLICK,GetDoubleClickTime(),NULL);
        Edit_LbuttonDblclk(hWnd,lParam);
        break;

    case WM_TIMER:
        if (wParam==TIMER_TRIPLECLICK) bDoubleClick=FALSE;
        break;

    case WM_RBUTTONUP:
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) {
        	OutputDebugString("Hosed #1.\r\n");
        	break;
        }	
        fpScr=(SCREEN *)GlobalLock(hgScr);
        if (fpScr == NULL) {
        	OutputDebugString("Hosed #2.\r\n");
        	break;
        }
        Edit_Copy(hWnd);
        Edit_ClearSelection(fpScr);                
        Edit_Paste(hWnd);
        GlobalUnlock(hgScr);
        break;
                            
    case WM_MOUSEMOVE:
        if (bMouseDown) Edit_MouseMove(hWnd,lParam);
        break;
        
    case WM_RBUTTONDOWN: {
        HSCREENLINE hgScrLine;
        SCREENLINE *fpScrLine;
        
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) {
        	OutputDebugString("Hosed #1.\r\n");
        	break;
        }	
        fpScr=(SCREEN *)GlobalLock(hgScr);
        if (fpScr == NULL) {
        	OutputDebugString("Hosed #2.\r\n");
        	break;
        }
        hgScrLine=fpScr->screen_top;
        fpScrLine=LINE_MEM_LOCK(hgScrLine);

//        wsprintf(strTmp,"fp->x=%d fp->y=%d text=%s \r\n",fpScr->x,fpScr->y,fpScrLine->text);
//        OutputDebugString(strTmp);
        LINE_MEM_LOCK(hgScrLine);
        }        
        break;
            
    case WM_PAINT:        
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr == NULL) {
        	OutputDebugString("Hosed #1.\r\n");
        	break;
        }	
        fpScr=(SCREEN *)GlobalLock(hgScr);
        if (fpScr == NULL) {
        	OutputDebugString("Hosed #2.\r\n");
        	break;
        }
        BeginPaint (hWnd,&ps);
        SelectObject(ps.hdc,fpScr->ghSelectedFont);
        hslLine=fpScr->screen_bottom;
        if (hslLine==NULL) {
            OutputDebugString("screen_bottom is NULL.\r\n");
            EndPaint(hWnd,&ps);                
            GlobalUnlock(hgScr);
            break;
        }
        DrawTextScreen(ps.rcPaint, fpScr, ps.hdc);
        EndPaint(hWnd,&ps);                
        DrawCursor(fpScr);
        GlobalUnlock(hgScr);
        break;         

    case WM_CLOSE:
#ifdef FILE_DEBUG
        _lclose(fh);
#endif
        if (MessageBox(hWnd,"Terminate this connection?","Telnet",MB_OKCANCEL) == IDOK) {
            hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
            if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
            fpScr=(SCREEN *)GlobalLock(hgScr);
            if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");
            SendMessage(fpScr->hwndTel,WM_MYSCREENCLOSE,NULL,(HSCREEN)hgScr);
            return (DefWindowProc(hWnd, message, wParam, lParam));
        }    
        break;

    case WM_DESTROY:
        hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
        if (hgScr != NULL) {
	        fpScr=(SCREEN *)GlobalLock(hgScr);
	        if (fpScr != NULL)
                DeleteObject(fpScr->ghSelectedFont);
		}
        return (DefWindowProc(hWnd, message, wParam, lParam));

    case WM_ACTIVATE:
    	if (wParam!=WA_INACTIVE) {
            hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
            if (hgScr == NULL) return (DefWindowProc(hWnd, message, wParam, lParam));
            fpScr=(SCREEN *)GlobalLock(hgScr);
            if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");
            if (fpScr->bAlert) {
                char strTitle[128];
                int idx;

                GetWindowText(hWnd,strTitle,sizeof(strTitle));
                if (strTitle[0] == ALERT) {
                    idx=lstrlen(strTitle);
                    strTitle[idx-2]=0;
                    SetWindowText(hWnd,&strTitle[2]);
                    fpScr->bAlert=FALSE;
                }
            }
            GlobalUnlock(hgScr);
        }  /* Allow control to drop down to DefWindowProc() */
        return (DefWindowProc(hWnd, message, wParam, lParam));
        break;

	case WM_SIZE:
		if (wParam == SIZE_MINIMIZED)
			break;

		hgScr = (HGLOBAL) GetWindowWord(hWnd, SCREEN_HANDLE);
		if (hgScr == NULL)
			break;
		fpScr = (SCREEN *) GlobalLock(hgScr);
		if (fpScr == NULL)
			break;

		if (SetInternalScreenSize(fpScr, LOWORD(lParam), HIWORD(lParam))) {
			SendMessage(fpScr->hwndTel, WM_MYSCREENSIZE, 0,
				MAKELONG(fpScr->width, fpScr->height));
			MakeWindowTitle(fpScr->title,fpScr->width,fpScr->height,title,sizeof(title));
            SetWindowText(hWnd,title);
		}

		GlobalUnlock(hgScr);
		break;

	case WM_SETFOCUS:
		hgScr = (HGLOBAL) GetWindowWord(hWnd, SCREEN_HANDLE);
		if (hgScr == NULL)
			break;
		fpScr = (SCREEN *) GlobalLock(hgScr);
		if (fpScr == NULL)
			break;

		CreateCaret(hWnd, NULL, fpScr->cxChar, 2);
		ScreenCursorOn(fpScr);
		break;

	case WM_KILLFOCUS:
		DestroyCaret();
		break;

    default:              /* Passes it on if unproccessed    */
        return (DefWindowProc(hWnd, message, wParam, lParam));
    }

    return (NULL);
}

/**************************************************************************
*                                                                         *
*  Function:  ReportError(WORD)                                           *
*                                                                         *
*   Purpose:  To report an error that has occurred while allocating       *
*             memory for the CD struct, locking the memory or while       *
*             trying to load a resource string.                           *
*                                                                         *
*   Returns:  void                                                        *
*                                                                         *
*  Comments:                                                              *
*                                                                         *
*   History:  Date      Reason                                            *
*             --------  -----------------------------------               *
*                                                                         *
*             10/01/91  Created                                           *
*                                                                         *
**************************************************************************/
void ReportError(WORD wErrorType){
   LPSTR lpszErrorMsg;

   switch( wErrorType )
      {
         case IDC_ALLOCFAIL:

            lpszErrorMsg=gszAllocErrorMsg;
            break;

         case IDC_LOCKFAIL:

            lpszErrorMsg=gszLockErrorMsg;
            break;

         case IDC_LOADSTRINGFAIL:

            lpszErrorMsg=gszLoadStrFail;
            break;

         default:    //let's hope we never get here!
            return;
      }

   MessageBox(NULL, (LPSTR)lpszErrorMsg, NULL, MB_OK);

   return;
}

void ScreenBell(SCREEN *fpScr) {
    MessageBeep(MB_ICONEXCLAMATION);
    if (fpScr->hWnd != GetActiveWindow()) {
        char strTitle[128];
        int idx;

        FlashWindow(fpScr->hWnd,TRUE);
        if (!fpScr->bAlert) {
            strTitle[0]=ALERT;
            strTitle[1]=SPACE;
            GetWindowText(fpScr->hWnd,&strTitle[2],sizeof(strTitle)-2);
            idx=lstrlen(strTitle);
            strTitle[idx]=SPACE;
            strTitle[idx+1]=ALERT;
            strTitle[idx+2]=0;
            SetWindowText(fpScr->hWnd,strTitle);
        }
        FlashWindow(fpScr->hWnd,FALSE);
        fpScr->bAlert=TRUE;
    }
}

void ScreenBackspace(SCREEN * fpScr) {
    RECT rc;
    
//    hDC=GetDC(fpScr->hWnd);
//    SelectObject(hDC,fpScr->ghSelectedFont);
//    TextOut(hDC,fpScr->x*fpScr->cxChar,fpScr->y*fpScr->cyChar," ",1);
//    ReleaseDC(fpScr->hWnd,hDC);
    rc.left=fpScr->x*fpScr->cxChar;
    rc.right=((fpScr->x+1)*fpScr->cxChar);
    rc.top=(fpScr->cyChar*fpScr->y);    
    rc.bottom=(fpScr->cyChar*fpScr->y+1);
    InvalidateRect(fpScr->hWnd,&rc,TRUE);
    fpScr->x--;
    if (fpScr->x < 0) fpScr->x=0;
//    DrawCursor(fpScr);
    UpdateWindow(fpScr->hWnd);
    
}

void ScreenTab(SCREEN *fpScr) {
    int num_spaces,idx;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    int iTest=0;
    
    num_spaces = TAB_SPACES - (fpScr->x % TAB_SPACES);
    if ((fpScr->x + num_spaces) >= fpScr->width) {
       ScreenScroll(fpScr);
       num_spaces -= fpScr->width - fpScr->x;
       fpScr->x=0;
    }
//    hgScrLine=fpScr->buffer_bottom;
    hgScrLine=GetScreenLineFromY(fpScr,fpScr->y);
    if (hgScrLine==NULL) return;
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
    if (fpScrLine==NULL) return;
    for (idx=0; idx<num_spaces; idx++,fpScr->x++) {
        if (!fpScrLine->text[fpScr->x])
            iTest=1;
        if (iTest)
            fpScrLine->text[fpScr->x]=SPACE;
    }
//    fpScrLine->text[fpScr->x]=0;
    hDC=GetDC(fpScr->hWnd);
    SelectObject(hDC,fpScr->ghSelectedFont);
    TextOut(hDC,(fpScr->x-num_spaces)*fpScr->cxChar,fpScr->y*fpScr->cyChar,
        fpScrLine->text+fpScr->x-num_spaces,num_spaces);
    ReleaseDC(fpScr->hWnd,hDC);                
    LINE_MEM_UNLOCK(hgScrLine);
    DrawCursor(fpScr);
}

void ScreenCarriageFeed(SCREEN *fpScr) {
    DrawCursor(fpScr);
    fpScr->x=0;    
}
