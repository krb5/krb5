extern long FAR PASCAL ScreenWndProc(HWND,UINT,WPARAM,LPARAM);

//#define WINMEM

/*
*          Definition of attribute bits in the Virtual Screen
*
*          0   -   Bold
*          1   -   
*          2   -
*          3   -   Underline
*          4   -   Blink
*          5   -
*          6   -   Reverse
*          7   -   Graphics character set
*
*/
#define SCR_isbold(x)   (x & 0x01)
#define SCR_isundl(x)   (x & 0x08)
#define SCR_isblnk(x)   (x & 0x10)
#define SCR_isrev(x)    (x & 0x40)
#define SCR_setrev(x)   (x ^= 0x40)
#define SCR_isgrph(x)   (x & 0x80)
#define SCR_inattr(x)   (x & 0xd9)
#define SCR_graph(x)    (x | 0x80)
#define SCR_notgraph(x) (x & 0x7F)

#define SCREEN_HANDLE            0    /* offset in extra window info */

#define WM_MYSCREENCHAR			(WM_USER+1)
#define WM_MYSCREENBLOCK		(WM_USER+2)
#define WM_MYSYSCHAR 			(WM_USER+3)
#define WM_MYSCREENCLOSE		(WM_USER+4)
#define WM_MYSCREENCHANGEBKSP	(WM_USER+5)
#define WM_MYSCREENSIZE			(WM_USER+6)
#define WM_NETWORKEVENT			(WM_USER+7)
#define WM_HOSTNAMEFOUND		(WM_USER+8)

#define FRAME_HEIGHT ((2* GetSystemMetrics(SM_CYFRAME))+GetSystemMetrics(SM_CYCAPTION)+GetSystemMetrics(SM_CYMENU)+3)
#define FRAME_WIDTH  (2*GetSystemMetrics(SM_CXFRAME)+GetSystemMetrics(SM_CXVSCROLL))
#define TAB_SPACES 8
#define SPACE 32
#define ALERT 0x21
#define MAX_LINE_WIDTH 256 /* not restricted to 1 byte */

#ifdef WINMEM
#define HSCREENLINE DWORD
#define LINE_MEM_ALLOC(x) sAlloc(x)
#define LINE_MEM_LOCK(x) (SCREENLINE *)sLock(x)
#define LINE_MEM_UNLOCK(x) sUnlock(x)
#define LINE_MEM_FREE(x) sFree(x)
#else
#define HSCREENLINE HGLOBAL
#define LINE_MEM_ALLOC(x) GlobalAlloc(GHND,x)
#define LINE_MEM_LOCK(x) (SCREENLINE *) GlobalLock(x)
#define LINE_MEM_UNLOCK(x) GlobalUnlock(x)
#define LINE_MEM_FREE(x) GlobalFree(x)
#endif

#define HSCREEN HGLOBAL

typedef struct SCREENLINE {
	HSCREENLINE next;
	HSCREENLINE prev;
	int width;
	char *text;
	char *attrib;
	char buffer[0];
} SCREENLINE;

typedef struct SCREEN {
    LPSTR title;
    HWND hWnd;
    HWND hwndTel;
    HSCREENLINE screen_top,
                screen_bottom,
                buffer_top,
                buffer_bottom;
	int ID,
        type,
        width,
        height,
        maxlines,       //Maximum number of scrollback lines
        numlines,       //Current number of scrollback lines
        savelines,      //Save lines off top?
        ESscroll,       //Scroll screen when ES received
        attrib,         //current attribute
        x,y,            //current cursor position
        Oldx,Oldy,      // internally used to redraw cursor
        Px,Py,Pattrib,  //saved cursor pos and attribute
        VSIDC,          // Insert/Delete character mode 0=draw line
        DECAWM,         // AutoWrap mode 0=off
        DECCKM,         // Cursor key mode
        DECPAM,         // keyPad Application mode
        IRM,            // Insert/Replace mode
        escflg,         // Current Escape level        
        top,bottom,     // Vertical bounds of screen
        parmptr,
        cxChar,         /* Width of the current font */
        cyChar;         /* Height of the current font */
    BOOL bAlert;
    int parms[6];       //Ansi Params
    LOGFONT lf;
    HFONT ghSelectedFont,ghSelectedULFont;
    char tabs[MAX_LINE_WIDTH];
    HSCREEN next, prev;
} SCREEN;

typedef struct CONFIG {
    LPSTR title;
    HWND hwndTel;
    int ID,
        type,
        height,
        width,
        maxlines,       //Maximum number of scrollback lines
        backspace,
        ESscroll,       //Scroll screen when ES received
        VSIDC,          // Insert/Delete character mode 0=draw line
        DECAWM,         // AutoWrap mode 0=off
        IRM;            // Insert/Replace mode
} CONFIG;

#define TELNET_SCREEN   0
#define CONSOLE_SCREEN  1

#define IDM_FONT        100
#define IDM_BACKSPACE   101
#define IDM_DELETE      102

#define IDM_COPY        200
#define IDM_PASTE       201
#define IDM_DEBUG       202

#define TIMER_TRIPLECLICK 1000

#define IDC_ALLOCFAIL           1
#define IDC_LOCKFAIL            2
#define IDC_LOADSTRINGFAIL      3
#define IDC_FONT                6

#define DESIREDPOINTSIZE 12


void        ReportError(WORD);
LPSTR NEAR AllocAndLockMem(HANDLE *hChunk, WORD wSize);
void NEAR InitializeStruct(WORD wCommDlgType, LPSTR lpStruct, HWND hWnd);

void ScreenInit(HANDLE hInstance);
HSCREENLINE ScreenNewLine();
void ScreenBell(SCREEN *fpScr);
void ScreenBackspace(SCREEN * fpScr);
void ScreenTab(SCREEN *fpScr);
void ScreenCarriageFeed(SCREEN *fpScr);
int ScreenScroll(SCREEN *fpScr);
void DeleteTopLine(SCREEN *fpScr);
/* emul.c */
void ScreenEm(LPSTR c,int len,HSCREEN hsScr);


/* intern.c */
HSCREENLINE GetScreenLineFromY(SCREEN *fpScr,int y);
HSCREENLINE ScreenClearLine(SCREEN *fpScr,HSCREENLINE hgScrLine);
void ScreenUnscroll(SCREEN *fpScr);
void ScreenELO(SCREEN *fpScr,int s);
void ScreenEraseScreen(SCREEN *fpScr);
void ScreenTabClear(SCREEN *fpScr);
void ScreenTabInit(SCREEN *fpScr);
void ScreenReset(SCREEN *fpScr);
void ScreenIndex(SCREEN * fpScr);
void ScreenWrapNow(SCREEN *fpScr,int *xp,int *yp);
void ScreenEraseToEOL(SCREEN *fpScr);
void ScreenEraseToBOL(SCREEN *fpScr);
void ScreenEraseLine(SCREEN *fpScr,int s);
void ScreenEraseToEndOfScreen(SCREEN *fpScr);
void ScreenRange(SCREEN *fpScr);
void ScreenAlign(SCREEN *fpScr);
void ScreenApClear(SCREEN *fpScr);
int ScreenInsChar(SCREEN *fpScr,int x);
void ScreenInsString(SCREEN *fpScr,int len,char *start);
void ScreenSaveCursor(SCREEN *fpScr);
void ScreenRestoreCursor(SCREEN *fpScr);
void ScreenDraw(SCREEN *fpScr,int x,int y,int a,int len,char *c);
void ScreenCursorOff(SCREEN *fpScr);
void ScreenCursorOn(SCREEN *fpScr);
void ScreenDelChars(SCREEN *fpScr, int n);
void ScreenRevIndex(SCREEN *fpScr);
void ScreenDelLines(SCREEN *fpScr, int n, int s);
void ScreenInsLines(SCREEN *fpScr, int n, int s);
#ifdef _DEBUG
	BOOL CheckScreen(SCREEN *fpScr);
#endif

void ProcessFontChange(HWND hWnd);
void Edit_LbuttonDown(HWND hWnd,LPARAM lParam);
void Edit_LbuttonDblclk(HWND hWnd,LPARAM lParam);
void Edit_LbuttonUp(HWND hWnd, LPARAM lParam);
void Edit_TripleClick(HWND hWnd, LPARAM lParam);
void Edit_MouseMove(HWND hWnd, LPARAM lParam);
void Edit_ClearSelection(SCREEN *fpScr);
void Edit_Copy(HWND hWnd);
void Edit_Paste(HWND hWnd);

HSCREEN InitNewScreen(CONFIG *Config);


