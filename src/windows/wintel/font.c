#include <windows.h>
#include <commdlg.h>
#include "screen.h"
#include "ini.h"

LOGFONT lf;
HFONT hFont;
char szStyle[LF_FACESIZE];

void ProcessFontChange(HWND hWnd) {
    static DWORD dwFontColor;  /* Color of font if one has been selected */
    CHOOSEFONT cf;
    HDC hDC;
    SCREEN *fpScr;
    HGLOBAL hgScr;
    TEXTMETRIC tm;
    char buf[16];
        
    hgScr=(HGLOBAL)GetWindowWord(hWnd,SCREEN_HANDLE);
    if (hgScr == NULL) OutputDebugString("Hosed #1.\r\n");
    fpScr=(SCREEN *)GlobalLock(hgScr);
    if (fpScr == NULL) OutputDebugString("Hosed #2.\r\n");

    cf.lStructSize = sizeof(cf);
    cf.hwndOwner = hWnd;
    cf.lpLogFont = (LPLOGFONT)&(fpScr->lf);
    cf.lpszStyle = szStyle;
    cf.Flags = CF_INITTOLOGFONTSTRUCT; // | CF_USESTYLE;
    cf.Flags |= CF_SCREENFONTS;
//    cf.Flags |= CF_ANSIONLY;
    cf.Flags |= CF_FORCEFONTEXIST;
    cf.Flags |= CF_FIXEDPITCHONLY;
    cf.Flags |= CF_NOSIMULATIONS;
 
    if (ChooseFont(&cf)) {
      if (fpScr->ghSelectedFont) DeleteObject(fpScr->ghSelectedFont);

      fpScr->ghSelectedFont = CreateFontIndirect((LPLOGFONT)&(fpScr->lf));
      fpScr->lf.lfUnderline=TRUE;
      fpScr->ghSelectedULFont= CreateFontIndirect((LPLOGFONT)&(fpScr->lf));
      fpScr->lf.lfUnderline=FALSE;
      hDC=GetDC(hWnd);
      SelectObject(hDC,fpScr->ghSelectedFont);
      GetTextMetrics(hDC,(LPTEXTMETRIC)&tm);

      fpScr->cxChar = tm.tmAveCharWidth;
      fpScr->cyChar = tm.tmHeight+ tm.tmExternalLeading;
      ReleaseDC(hWnd,hDC);
      SetWindowPos(hWnd,NULL,0,0, fpScr->cxChar * fpScr->width + 
                    FRAME_WIDTH, fpScr->cyChar * fpScr->height +
                    FRAME_HEIGHT, SWP_NOMOVE|SWP_NOZORDER);

      dwFontColor=RGB(255, 255, 255);
      InvalidateRect(hWnd, NULL, TRUE);
    }

    WritePrivateProfileString(INI_FONT,"FaceName",fpScr->lf.lfFaceName,TELNET_INI);
    wsprintf(buf,"%d",(int)fpScr->lf.lfHeight);
    WritePrivateProfileString(INI_FONT,"Height",buf,TELNET_INI);
    wsprintf(buf,"%d",(int)fpScr->lf.lfWidth);
    WritePrivateProfileString(INI_FONT,"Width",buf,TELNET_INI);
    wsprintf(buf,"%d",(int)fpScr->lf.lfEscapement);
    WritePrivateProfileString(INI_FONT,"Escapement",buf,TELNET_INI);
    wsprintf(buf,"%d",(int)fpScr->lf.lfCharSet);
    WritePrivateProfileString(INI_FONT,"CharSet",buf,TELNET_INI);
    wsprintf(buf,"%d",(int)fpScr->lf.lfPitchAndFamily);
    WritePrivateProfileString(INI_FONT,"PitchAndFamily",buf,TELNET_INI);
    
    GlobalUnlock(hgScr);
    return;
}

void NEAR InitializeStruct(WORD wCommDlgType, LPSTR lpStruct, HWND hWnd)
{
   LPCHOOSEFONT        lpFontChunk;
   
   switch (wCommDlgType)
      {      
      case IDC_FONT:

         lpFontChunk = (LPCHOOSEFONT)lpStruct;

         lpFontChunk->lStructSize    = sizeof(CHOOSEFONT);
         lpFontChunk->hwndOwner      = hWnd;

//The hDC field will be initialized when we return--this avoids passing
//the hDC in or getting the DC twice.
//The LOGFONT field will also be initialized when we get back.
//            lpFontChunk->hDC            = hDC;
//            lpFontChunk->lpLogFont      = &lf;

         lpFontChunk->Flags          = CF_SCREENFONTS | CF_FIXEDPITCHONLY |
                                       CF_INITTOLOGFONTSTRUCT | CF_APPLY;
         lpFontChunk->rgbColors      = RGB(0, 0, 255);
         lpFontChunk->lCustData      = 0L;
         lpFontChunk->lpfnHook       = NULL;
         lpFontChunk->lpTemplateName = (LPSTR)NULL;
         lpFontChunk->hInstance      = (HANDLE)NULL;
         lpFontChunk->lpszStyle      = (LPSTR)NULL;
         lpFontChunk->nFontType      = SCREEN_FONTTYPE;
         lpFontChunk->nSizeMin       = 0;
         lpFontChunk->nSizeMax       = 0;
         break;
      default:
         break;
      }
   return;
}

LPSTR NEAR AllocAndLockMem(HANDLE *hChunk, WORD wSize) {
   LPSTR lpChunk;

   *hChunk = GlobalAlloc(GMEM_FIXED, wSize);
   if (*hChunk) {
       lpChunk = GlobalLock(*hChunk);
       if (!lpChunk) {
           GlobalFree(*hChunk);
           ReportError(IDC_LOCKFAIL);
           lpChunk=NULL;
       }
   } else {
       ReportError(IDC_ALLOCFAIL);
       lpChunk=NULL;
   }
   return(lpChunk);
}


