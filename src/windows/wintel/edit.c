#include <windows.h>
#include <commdlg.h>
#include <ctype.h>
#include "screen.h"

char *cInvertedArray;
int bMouseDown=FALSE;
int iLocStart,iLocEnd,bSelection;

void Edit_LbuttonDown(HWND hWnd,LPARAM lParam) {
    SCREEN *fpScr;
    HGLOBAL hgScr;
    HMENU hMenu;
    int iTmp,iXlocStart,iYlocStart;
    HDC hDC;
    
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
    fpScr=(SCREEN *)GlobalLock(hgScr);
    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");
    
    hDC=GetDC(hWnd);
    for (iTmp=0; iTmp < fpScr->width*fpScr->height; iTmp++) {        
        if (cInvertedArray[iTmp]) {
            PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
            cInvertedArray[iTmp]=0;                    
        }    
    }
    bSelection=FALSE;
    hMenu=GetMenu(hWnd);
    EnableMenuItem(hMenu,IDM_COPY,MF_GRAYED);
    ReleaseDC(hWnd,hDC);
    iXlocStart=(int)LOWORD(lParam)/fpScr->cxChar;
	if (iXlocStart >= fpScr->width)
		iXlocStart = fpScr->width - 1;
    iYlocStart=(int)HIWORD(lParam)/fpScr->cyChar;
	if (iYlocStart >= fpScr->height)
		iYlocStart = fpScr->height - 1;
    iLocStart=iXlocStart+(iYlocStart*fpScr->width);
    bMouseDown=TRUE;
    GlobalUnlock(hgScr);
}

void Edit_LbuttonUp(HWND hWnd, LPARAM lParam) {
    SCREEN *fpScr;
    HGLOBAL hgScr;
    int iTmp,iTmp2;
    HMENU hMenu;
    
    bMouseDown=FALSE;
    if (bSelection) return;
    bSelection=TRUE;
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
    fpScr=(SCREEN *)GlobalLock(hgScr);
    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");        
    iTmp=(int)LOWORD(lParam)/fpScr->cxChar;
	if (iTmp >= fpScr->width)
		iTmp = fpScr->width - 1;
    iTmp2=(int)HIWORD(lParam)/fpScr->cyChar;
	if (iTmp2 >= fpScr->height)
		iTmp2 = fpScr->height - 1;
    GlobalUnlock(hgScr);
    iLocEnd=iTmp+(iTmp2*fpScr->width);
    if (iLocEnd==iLocStart) {
        bSelection=FALSE;
    } else {
        hMenu=GetMenu(hWnd);
        EnableMenuItem(hMenu,IDM_COPY,MF_ENABLED);
    }    
}    
    
void Edit_MouseMove(HWND hWnd, LPARAM lParam){
    SCREEN *fpScr;
    HGLOBAL hgScr;
    int iTmp,iTmp2,iXlocCurr,iYlocCurr,iLocCurr,iX,iX2,iY,iY2;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
    HDC hDC;
    
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
    fpScr=(SCREEN *)GlobalLock(hgScr);
    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");
    hDC = GetDC(hWnd);
    iXlocCurr=(int)LOWORD(lParam)/fpScr->cxChar;
	if (iXlocCurr >= fpScr->width)
		iXlocCurr = fpScr->width - 1;
    iYlocCurr=(int)HIWORD(lParam)/fpScr->cyChar;
	if (iYlocCurr >= fpScr->height)
		iYlocCurr = fpScr->height - 1;
    iLocCurr=iXlocCurr+(iYlocCurr*fpScr->width);
    if (iLocCurr > iLocStart) {    
        for (iTmp=0; iTmp < iLocStart; iTmp++) {        
            if (cInvertedArray[iTmp]) {
                PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                    fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
                cInvertedArray[iTmp]=0;                    
            }    
        }
        iX=(iLocStart%fpScr->width);
        iY=(int)(iLocStart/fpScr->width);
        iX2=(iLocCurr%fpScr->width);
        iY2=(int)(iLocCurr/fpScr->width);
        if (iY==iY2) {
            hgScrLine=GetScreenLineFromY(fpScr,iY);
            fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
            for (iTmp2= iX; iTmp2 < iX2; iTmp2++) {
                if ((!cInvertedArray[iTmp2+(fpScr->width*iY)])&& fpScrLine->text[iTmp2]) {
                    PatBlt(hDC,(iTmp2)*fpScr->cxChar,iY*fpScr->cyChar,
                        fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                    cInvertedArray[iTmp2+(fpScr->width*iY)]=fpScrLine->text[iTmp2];
                }    
            }    
            LINE_MEM_UNLOCK(hgScrLine);
        }            
        else {
            hgScrLine=GetScreenLineFromY(fpScr,iY);
            fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
            for (iTmp2= iX; iTmp2 < fpScr->width; iTmp2++) {
                if ((!cInvertedArray[iTmp2+(fpScr->width*iY)])&& fpScrLine->text[iTmp2]) {
                    PatBlt(hDC,(iTmp2)*fpScr->cxChar,iY*fpScr->cyChar,
                        fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                    cInvertedArray[iTmp2+(fpScr->width*iY)]=fpScrLine->text[iTmp2];
                }    
            }                
            for (iTmp=iY+1; iTmp < iY2; iTmp++) {
                hgScrLine=GetScreenLineFromY(fpScr,iTmp);
                fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
                for (iTmp2= 0; iTmp2 < fpScr->width; iTmp2++) {
                    if ((!cInvertedArray[iTmp2+(fpScr->width*iTmp)])&& fpScrLine->text[iTmp2]) {
                        PatBlt(hDC,(iTmp2)*fpScr->cxChar,iTmp*fpScr->cyChar,
                            fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                        cInvertedArray[iTmp2+(fpScr->width*iTmp)]=fpScrLine->text[iTmp2];
                    }    
                }    
                LINE_MEM_UNLOCK(hgScrLine);
            }
            if (!(iY2==iY)) {
                hgScrLine=GetScreenLineFromY(fpScr,iY2);
                fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
                for (iTmp2= 0; iTmp2 < iX2; iTmp2++) {
                    if ((!cInvertedArray[iTmp2+(fpScr->width*iY2)])&& fpScrLine->text[iTmp2]) {
                        PatBlt(hDC,(iTmp2)*fpScr->cxChar,iY2*fpScr->cyChar,
                            fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                        cInvertedArray[iTmp2+(fpScr->width*iY2)]=fpScrLine->text[iTmp2];
                    }    
                }    
                LINE_MEM_UNLOCK(hgScrLine);                
            }                

        }    
        for (iTmp=iLocCurr; iTmp < fpScr->width*fpScr->height; iTmp++) {        
            if (cInvertedArray[iTmp]) {
                PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                    fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
                cInvertedArray[iTmp]=0;                    
            }    
        }
    } else { /* going backwards */
        for (iTmp=0; iTmp < iLocCurr; iTmp++) {        
            if (cInvertedArray[iTmp]) {
                PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                    fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
                cInvertedArray[iTmp]=0;                    
            }    
        }
        iX=(iLocCurr%fpScr->width);
        iY=(int)(iLocCurr/fpScr->width);
        iX2=(iLocStart%fpScr->width);
        iY2=(int)(iLocStart/fpScr->width);
        if (iY==iY2) {
            hgScrLine=GetScreenLineFromY(fpScr,iY);
            fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
            for (iTmp2= iX; iTmp2 < iX2; iTmp2++) {
                if ((!cInvertedArray[iTmp2+(fpScr->width*iY)])&& fpScrLine->text[iTmp2]) {
                    PatBlt(hDC,(iTmp2)*fpScr->cxChar,iY*fpScr->cyChar,
                        fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                    cInvertedArray[iTmp2+(fpScr->width*iY)]=fpScrLine->text[iTmp2];
                }    
            }    
            LINE_MEM_UNLOCK(hgScrLine);
        }            
        else {
            hgScrLine=GetScreenLineFromY(fpScr,iY);
            fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
            for (iTmp2= iX; iTmp2 < fpScr->width; iTmp2++) {
                if ((!cInvertedArray[iTmp2+(fpScr->width*iY)])&& fpScrLine->text[iTmp2]) {
                    PatBlt(hDC,(iTmp2)*fpScr->cxChar,iY*fpScr->cyChar,
                        fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                    cInvertedArray[iTmp2+(fpScr->width*iY)]=fpScrLine->text[iTmp2];
                }    
            }                
            for (iTmp=iY+1; iTmp < iY2; iTmp++) {
                hgScrLine=GetScreenLineFromY(fpScr,iTmp);
                fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
                for (iTmp2= 0; iTmp2 < fpScr->width; iTmp2++) {
                    if ((!cInvertedArray[iTmp2+(fpScr->width*iTmp)])&& fpScrLine->text[iTmp2]) {
                        PatBlt(hDC,(iTmp2)*fpScr->cxChar,iTmp*fpScr->cyChar,
                            fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                        cInvertedArray[iTmp2+(fpScr->width*iTmp)]=fpScrLine->text[iTmp2];
                    }    
                }    
                LINE_MEM_UNLOCK(hgScrLine);
            }
            if (!(iY2==iY)) {
                hgScrLine=GetScreenLineFromY(fpScr,iY2);
                fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
                for (iTmp2= 0; iTmp2 < iX2; iTmp2++) {
                    if ((!cInvertedArray[iTmp2+(fpScr->width*iY2)])&& fpScrLine->text[iTmp2]) {
                        PatBlt(hDC,(iTmp2)*fpScr->cxChar,iY2*fpScr->cyChar,
                            fpScr->cxChar,fpScr->cyChar,DSTINVERT);
                        cInvertedArray[iTmp2+(fpScr->width*iY2)]=fpScrLine->text[iTmp2];
                    }    
                }    
                LINE_MEM_UNLOCK(hgScrLine);                
            }                

        }    
        for (iTmp=iLocStart; iTmp < fpScr->width*fpScr->height; iTmp++) {        
            if (cInvertedArray[iTmp]) {
                PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                    fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
                cInvertedArray[iTmp]=0;                    
            }    
        }
        
    }            
    ReleaseDC(hWnd,hDC);
    GlobalUnlock(hgScr);
}

void Edit_ClearSelection(SCREEN *fpScr) {
    int iTmp;
    HDC hDC;
    HMENU hMenu;

    hDC=GetDC(fpScr->hWnd);
    for (iTmp=0; iTmp < fpScr->width*fpScr->height; iTmp++) {        
        if (cInvertedArray[iTmp]) {
            PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
            cInvertedArray[iTmp]=0;                    
        }    
    }
    bSelection=FALSE;
    hMenu=GetMenu(fpScr->hWnd);
    EnableMenuItem(hMenu,IDM_COPY,MF_GRAYED);    
    ReleaseDC(fpScr->hWnd,hDC);
}    

void Edit_Copy(HWND hWnd) {
    int iTmp,iIdx;
    HGLOBAL hCutBuffer;
    LPSTR lpCutBuffer;
    SCREEN *fpScr;
    HGLOBAL hgScr;
    
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
    fpScr=(SCREEN *)GlobalLock(hgScr);

    hCutBuffer= GlobalAlloc(GHND,(DWORD)(fpScr->width*fpScr->height+1));
    lpCutBuffer= GlobalLock(hCutBuffer);

    if (iLocStart > iLocEnd) { /* swap variables */
        iTmp=iLocStart;
        iLocStart=iLocEnd;
        iLocEnd=iLocStart;
    }        
    iTmp=iLocStart;
    iIdx=0;
    while (iTmp < iLocEnd) {
        if (!cInvertedArray[iTmp]) {
            lpCutBuffer[iIdx++]='\r';
            lpCutBuffer[iIdx++]='\n';
            iTmp= (((int)(iTmp/fpScr->width))+1)*fpScr->width;            
            continue;
        }
        lpCutBuffer[iIdx++]=cInvertedArray[iTmp++];
    }
    lpCutBuffer[iIdx]=0;
    GlobalUnlock(hCutBuffer);
    OpenClipboard(hWnd);
    EmptyClipboard();
    SetClipboardData(CF_TEXT,hCutBuffer);
    CloseClipboard();
}

void Edit_Paste(HWND hWnd) {
    HGLOBAL hClipMemory;
    static HGLOBAL hMyClipBuffer;
    LPSTR lpClipMemory,lpMyClipBuffer;
    HGLOBAL hgScr;
	SCREEN *fpScr;                              
    
    if (hMyClipBuffer) GlobalFree(hMyClipBuffer);
    OpenClipboard(hWnd);
    hClipMemory = GetClipboardData(CF_TEXT);
    hMyClipBuffer = GlobalAlloc(GHND,GlobalSize(hClipMemory));
    lpMyClipBuffer= GlobalLock(hMyClipBuffer);
    lpClipMemory= GlobalLock(hClipMemory);
    
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
	fpScr=(SCREEN *)GlobalLock(hgScr);
    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");

    lstrcpy(lpMyClipBuffer,lpClipMemory);
//    OutputDebugString(lpMyClipBuffer);
    PostMessage(fpScr->hwndTel,WM_MYSCREENBLOCK,(WPARAM)hMyClipBuffer,
                    (HSCREEN)hgScr);                
    CloseClipboard();                    
    GlobalUnlock(hClipMemory);
    GlobalUnlock(hMyClipBuffer);    
}

void Edit_LbuttonDblclk(HWND hWnd,LPARAM lParam) {
    HDC hDC;
    SCREEN *fpScr;
    HGLOBAL hgScr;
    int iTmp,iTmp2,iXlocStart,iYloc;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
        
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
    fpScr=(SCREEN *)GlobalLock(hgScr);
    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");
    
    hDC=GetDC(hWnd);
    for (iTmp=0; iTmp < fpScr->width*fpScr->height; iTmp++) {        
        if (cInvertedArray[iTmp]) {
            PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
            cInvertedArray[iTmp]=0;                    
        }    
    }
    bSelection=FALSE;
    iXlocStart=(int)LOWORD(lParam)/fpScr->cxChar;
	if (iXlocStart >= fpScr->width)
		iXlocStart = fpScr->width - 1;
    iYloc=(int)HIWORD(lParam)/fpScr->cyChar;
	if (iYloc >= fpScr->height)
		iYloc = fpScr->height - 1;
    iLocStart=iXlocStart+(iYloc*fpScr->width);
    
    hgScrLine=GetScreenLineFromY(fpScr,iYloc);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
    
    iTmp=iXlocStart;
    while (isalnum((int)fpScrLine->text[iTmp])) {
        PatBlt(hDC,iTmp*fpScr->cxChar,iYloc*fpScr->cyChar,
             fpScr->cxChar,fpScr->cyChar,DSTINVERT);                    
        cInvertedArray[iTmp+(iYloc*fpScr->width)]=fpScrLine->text[iTmp];
        iTmp++;
    }
    iTmp2=iXlocStart-1;
    while (isalnum((int)fpScrLine->text[iTmp2])) {
        PatBlt(hDC,iTmp2*fpScr->cxChar,iYloc*fpScr->cyChar,
             fpScr->cxChar,fpScr->cyChar,DSTINVERT);                        
        cInvertedArray[iTmp2+(iYloc*fpScr->width)]=fpScrLine->text[iTmp2];
        iTmp2--;
    }    
    iLocStart=(iTmp2+1)+(iYloc*fpScr->width);
    iLocEnd=(iTmp)+(iYloc*fpScr->width);        

    bSelection=TRUE;
    ReleaseDC(hWnd,hDC);
    LINE_MEM_UNLOCK(hgScrLine);        
    GlobalUnlock(hgScr);
}

void Edit_TripleClick(HWND hWnd,LPARAM lParam) {
    HDC hDC;
    SCREEN *fpScr;
    HGLOBAL hgScr;
    int iTmp,iYloc;
    HSCREENLINE hgScrLine;
    SCREENLINE *fpScrLine;
        
//    OutputDebugString("Triple Click \r\n");
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
    fpScr=(SCREEN *)GlobalLock(hgScr);
    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");
    
    hDC=GetDC(hWnd);
    for (iTmp=0; iTmp < fpScr->width*fpScr->height; iTmp++) {        
        if (cInvertedArray[iTmp]) {
            PatBlt(hDC,(iTmp%fpScr->width)*fpScr->cxChar,(int)(iTmp/fpScr->width)*fpScr->cyChar,
                fpScr->cxChar,fpScr->cyChar,DSTINVERT);                
            cInvertedArray[iTmp]=0;                    
        }    
    }
    bSelection=FALSE;
    iYloc=(int)HIWORD(lParam)/fpScr->cyChar;
	if (iYloc >= fpScr->height)
		iYloc = fpScr->height - 1;
    iLocStart=(iYloc*fpScr->width);
    
    hgScrLine=GetScreenLineFromY(fpScr,iYloc);
    fpScrLine=(SCREENLINE *)LINE_MEM_LOCK(hgScrLine);
    
    for (iTmp=0; iTmp<fpScr->width; iTmp++) {
        if (fpScrLine->text[iTmp]) {
            PatBlt(hDC,iTmp*fpScr->cxChar,iYloc*fpScr->cyChar,
                 fpScr->cxChar,fpScr->cyChar,DSTINVERT);                    
            cInvertedArray[iTmp+(iYloc*fpScr->width)]=fpScrLine->text[iTmp];
        } else break;    
    }
    iLocEnd=(iTmp+(iYloc*fpScr->width));

    bSelection=TRUE;
    ReleaseDC(hWnd,hDC);
    LINE_MEM_UNLOCK(hgScrLine);        
    GlobalUnlock(hgScr);
}
