//	**************************************************************************************
//	File:			MainFrm.cpp
//	By:				Arthur David Leather
//	Created:		12/02/98
//	Copyright		@1998 Massachusetts Institute of Technology - All rights reserved.
//	Description:    CPP file for MainFrm.h. Contains variables and functions
//					for Leash
//
//	History:
//
//	MM/DD/YY	Inits	Description of Change
//	12/02/98	ADL		Original
//	**************************************************************************************


#include "stdafx.h"
#include "Leash.h"
#include "MainFrm.h"
#include "lglobals.h"
//#include "KrbRealmHostMaintenance.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CMainFrame

#define MIN_LEFT      179
#define MIN_TOP		  61
#define MIN_RIGHT	  530
#define MIN_BOTTOM	  280

CStatusBar CMainFrame::m_wndStatusBar;
CToolBar   CMainFrame::m_wndToolBar;
CImageList CMainFrame::m_imageList;
CImageList CMainFrame::m_disabledImageList;
BOOL	   CMainFrame::m_isMinimum;
BOOL       CMainFrame::m_isBeingResized;
int        CMainFrame::m_whatSide;

IMPLEMENT_DYNCREATE(CMainFrame, CLeashFrame)

BEGIN_MESSAGE_MAP(CMainFrame, CLeashFrame)
	//{{AFX_MSG_MAP(CMainFrame)
	ON_WM_CREATE()
	ON_COMMAND(ID_RESET_WINDOW_SIZE, OnResetWindowSize)
	ON_WM_SIZING()
    ON_WM_CLOSE()
	ON_WM_GETMINMAXINFO()
    ON_COMMAND(ID_APP_EXIT, OnClose)
	//}}AFX_MSG_MAP
	// Global help commands
	ON_COMMAND(ID_HELP_LEASH_, CMainFrame::OnHelpFinder)
	ON_COMMAND(ID_HELP, CMainFrame::OnHelp)
	ON_COMMAND(ID_CONTEXT_HELP, CMainFrame::OnContextHelp)
END_MESSAGE_MAP()

static UINT indicators[] =
{
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,
    ID_SEPARATOR,
    ID_SEPARATOR
};


/////////////////////////////////////////////////////////////////////////////
// CMainFrame construction/destruction

CMainFrame::CMainFrame()
{
	m_winRectLeft = 0;
	m_winRectTop = 0;
	m_winRectRight = 0;
	m_winRectBottom = 0;
	m_whatSide = RESET_MINSIZE;
	m_isMinimum = FALSE;
    m_isBeingResized = FALSE;
    m_bOwnerCreated = FALSE;
}

CMainFrame::~CMainFrame()
{
}

int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CLeashFrame::OnCreate(lpCreateStruct) == -1)
		return -1;

    ShowWindow(SW_HIDE);

/* NT4 and NT5 aren't shipped with a version of MFC that supports
// 'CreateEx()' as of 2/1/99
#if _MFC_VER > 0x0421

	if (!m_wndToolBar.CreateEx(this) ||
		!m_wndToolBar.LoadToolBar(IDR_MAINFRAME))
	{
		TRACE0("Failed to create toolbar\n");
		return -1;      // fail to create
	}

#else

	if (!m_wndToolBar.Create(this) ||
		!m_wndToolBar.LoadToolBar(IDR_MAINFRAME))
	{
		TRACE0("Failed to create toolbar\n");
		return -1;      // fail to create
	}

#endif
*/

	if (!m_wndToolBar.Create(this) ||
		!m_wndToolBar.LoadToolBar(IDR_MAINFRAME))
	{
		MessageBox("There is problem creating the Leash Toolbar!",
                   "Error", MB_OK);
        TRACE0("Failed to create toolbar\n");
		return -1;      // fail to create
	}

    // Create an image list of Icons so that we can use the best color
    // depth available on the system and then assign this new list to
    // be used instead of the single bitmap file assigned to the toolbar
    // in the resource file
    CToolBarCtrl *_toolBar = NULL;
    CToolBarCtrl& toolBar = CMainFrame::m_wndToolBar.GetToolBarCtrl();
    HICON      hIcon[7];
    int n;

    for (n = 0; n < 7; n++)
    {
        hIcon[n] = NULL;
    }

    UINT bitsPerPixel = GetDeviceCaps( ::GetDC(::GetDesktopWindow()), BITSPIXEL);
    UINT ilcColor;
    if ( bitsPerPixel >= 32 )
        ilcColor = ILC_COLOR32;
    else if ( bitsPerPixel >= 24 )
        ilcColor = ILC_COLOR24;
    else if ( bitsPerPixel >= 16 )
        ilcColor = ILC_COLOR16;
    else if ( bitsPerPixel >= 8 )
        ilcColor = ILC_COLOR8;
    else
        ilcColor = ILC_COLOR;

    m_imageList.Create(18, 18, ilcColor | ILC_MASK, 8, 4);
    m_imageList.SetBkColor(GetSysColor(COLOR_BTNFACE));

    hIcon[0] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_INIT);
    hIcon[1] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_RENEW);
    hIcon[2] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_IMPORT);
    hIcon[3] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_DESTROY);
    hIcon[4] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_PASSWORD);
    hIcon[5] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_REFRESH);
    hIcon[6] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_SYNC);

    for (n = 0; n < 7; n++)
    {
        m_imageList.Add(hIcon[n]);
    }
    toolBar.SetImageList(&m_imageList);

    m_disabledImageList.Create(18, 18, ilcColor | ILC_MASK, 8, 4);
    m_disabledImageList.SetBkColor(GetSysColor(COLOR_INACTIVECAPTIONTEXT));

    hIcon[0] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_INIT_DISABLED);
    hIcon[1] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_RENEW_DISABLED);
    hIcon[2] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_IMPORT_DISABLED);
    hIcon[3] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_DESTROY_DISABLED);
    hIcon[4] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_PASSWORD_DISABLED);
    hIcon[5] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_REFRESH_DISABLED);
    hIcon[6] = AfxGetApp()->LoadIcon(IDI_TOOLBAR_SYNC_DISABLED);

    for (n = 0; n < 7; n++)
    {
        m_disabledImageList.Add(hIcon[n]);
    }
    toolBar.SetDisabledImageList(&m_disabledImageList);

	if (!m_wndStatusBar.Create(this) ||
		!m_wndStatusBar.SetIndicators(indicators,
		  (CLeashApp::m_hAfsDLL ? 4 : 3)))
	{
		MessageBox("There is problem creating the Leash Status Bar!",
                   "Error", MB_OK);
        TRACE0("Failed to create status bar\n");
		return -1;      // fail to create
	}

	// TODO: Remove this if you don't want tool tips or a resizeable toolbar
	m_wndToolBar.SetBarStyle(m_wndToolBar.GetBarStyle() |
		                     CBRS_TOOLTIPS | CBRS_FLYBY | CBRS_SIZE_DYNAMIC);

	// TODO: Delete these three lines if you don't want the toolbar to
	//  be dockable
	m_wndToolBar.EnableDocking(CBRS_ALIGN_ANY);
	EnableDocking(CBRS_ALIGN_ANY);
	//DockControlBar(&m_wndToolBar);

	return 0;
}

BOOL CMainFrame::PreTranslateMessage(MSG* pMsg)
{
    if ( pMsg->message == WM_SYSCOMMAND && (pMsg->wParam & 0xfff0) == SC_CLOSE )
    {
        return TRUE;
    }
    return CLeashFrame::PreTranslateMessage(pMsg);
}

BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
	// Use the specific class name we established earlier
    // Remove the Minimize and Maximize buttons
    cs.style &= ~WS_MINIMIZEBOX;
    cs.style &= ~WS_MAXIMIZEBOX;
    // Initialize the extended window style to display a TaskBar entry with WS_EX_APPWINDOW
    cs.dwExStyle |= WS_EX_APPWINDOW;
    cs.dwExStyle |= WS_EX_OVERLAPPEDWINDOW ;
	cs.lpszClass = _T("LEASH.0WNDCLASS");
    cs.lpszName = _T("Leash32");

    CString strText = AfxGetApp()->GetProfileString(CLeashFrame::s_profileHeading,
                                                    CLeashFrame::s_profileRect);
    if (!strText.IsEmpty())
    {
        CRect rect;

        rect.left = atoi((const char*) strText);
        rect.top = atoi((const char*) strText + 5);
        rect.right = atoi((const char*) strText + 10);
        rect.bottom = atoi((const char*) strText + 15);

        cs.x = rect.left;
        cs.y = rect.top;
        cs.cx = rect.right - rect.left;
        cs.cy = rect.bottom - rect.top;

        if ( cs.x < 0 )
            cs.x = CW_USEDEFAULT;
        if ( cs.y < 0 )
            cs.y = CW_USEDEFAULT;
        if ( cs.cx <= 0 )
            cs.cx = CLeashFrame::s_rectDefault.right;
        if ( cs.cy <= 0 )
            cs.cy = CLeashFrame::s_rectDefault.bottom;
    }
    else
    {
        cs.cx = CLeashFrame::s_rectDefault.right;
        cs.cy = CLeashFrame::s_rectDefault.bottom;
        cs.y = CW_USEDEFAULT;
        cs.x = CW_USEDEFAULT;
    }

    // Change the following line to call
	// CLeashFrame::PreCreateWindow(cs) if this is an SDI application.
	if (!CLeashFrame::PreCreateWindow(cs))
        return FALSE;

    // We create a parent window for our application to ensure that
    // it has an owner.  This way we can disable the TaskBar entry
    // by removing the WS_EX_APPWINDOW style later on.
    if ( !m_bOwnerCreated )
    {
        m_bOwnerCreated = m_MainFrameOwner.Create(IDD_FRAMEOWNER);
        if ( m_bOwnerCreated )
            m_MainFrameOwner.ShowWindow(SW_HIDE);
    }
    if ( m_bOwnerCreated )
        cs.hwndParent = m_MainFrameOwner.GetSafeHwnd();

    return TRUE;
}


BOOL CMainFrame::ShowTaskBarButton(BOOL bVisible)
{
    if (!m_bOwnerCreated)
        return FALSE;

    if (bVisible) {
        ShowWindow(SW_HIDE);
        ModifyStyleEx(0, WS_EX_APPWINDOW);
        ShowWindow(SW_SHOW);
    } else {
        ShowWindow(SW_HIDE);
        ModifyStyleEx(WS_EX_APPWINDOW, 0);
        ShowWindow(SW_SHOW);
    }
    return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CMainFrame diagnostics

#ifdef _DEBUG
void CMainFrame::AssertValid() const
{
	CLeashFrame::AssertValid();
}

void CMainFrame::Dump(CDumpContext& dc) const
{
	CLeashFrame::Dump(dc);
}

#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CMainFrame message handlers

void CMainFrame::OnResetWindowSize()
{
    WINDOWPLACEMENT wndpl;
	wndpl.length = sizeof(WINDOWPLACEMENT);

    if (!GetWindowPlacement(&wndpl))
    {
        MessageBox("There is a problem getting Leash Window size!",
                   "Error", MB_OK);
        return;
    }

    wndpl.rcNormalPosition = CLeashFrame::s_rectDefault;

	m_whatSide = SKIP_MINSIZE;

    if (!SetWindowPlacement(&wndpl))
    {
        MessageBox("There is a problem setting Leash Window size!",
                   "Error", MB_OK);
    }

	m_whatSide = RESET_MINSIZE;
}

void CMainFrame::OnSizing(UINT fwSide, LPRECT pRect)
{ // Keeps track of Leash window size for function CMainFrame::RecalcLayout
	m_winRectLeft = pRect->left;
	m_winRectTop = pRect->top;
	m_winRectRight = pRect->right;
	m_winRectBottom = pRect->bottom;

	if (m_whatSide)
	  m_whatSide = fwSide;

	CLeashFrame::OnSizing(fwSide, pRect);
}

void CMainFrame::RecalcLayout(BOOL bNotify)
{ // MINSIZE - Insurance that we have a minimum Leash window size
	int width = MIN_RIGHT - MIN_LEFT;
	int height = MIN_BOTTOM - MIN_TOP;

    BOOL change = FALSE;
	WINDOWPLACEMENT wndpl;
	wndpl.length = sizeof(WINDOWPLACEMENT);

    if (!GetWindowPlacement(&wndpl))
    {
        MessageBox("There is a problem getting Leash Window size!",
                   "Error", MB_OK);
        return;
    }

	if (m_whatSide)
	{
		if ((m_winRectRight - m_winRectLeft) < width)
		{
			if (m_whatSide == LEFT_SIDE) {
                wndpl.rcNormalPosition.left = wndpl.rcNormalPosition.right - width;
                change = TRUE;
			} else if (m_whatSide == RIGHT_SIDE) {
                wndpl.rcNormalPosition.right = wndpl.rcNormalPosition.left + width;
                change = TRUE;
            }
		}
		else if ((m_winRectBottom - m_winRectTop) < height)
		{
			if (m_whatSide == TOP_SIDE) {
                wndpl.rcNormalPosition.top = wndpl.rcNormalPosition.bottom - height;
                change = TRUE;
			} else if (m_whatSide == BOTTOM_SIDE) {
                wndpl.rcNormalPosition.bottom = wndpl.rcNormalPosition.top + height;
                change = TRUE;
            }
		}
	}

    if ( change ) {
        if (!SetWindowPlacement(&wndpl))
        {
            MessageBox("There is a problem setting Leash Window size!",
                        "Error", MB_OK);
        }
    }
    m_isBeingResized = TRUE;

    CLeashFrame::RecalcLayout(bNotify);
}


void CMainFrame::OnGetMinMaxInfo(MINMAXINFO FAR* lpMMI)
{
    lpMMI->ptMinTrackSize.x = 650;
    lpMMI->ptMinTrackSize.y = 240;
	CLeashFrame::OnGetMinMaxInfo(lpMMI);
}

void CMainFrame::OnClose(void)
{
    CLeashFrame::OnClose();
}

LRESULT CMainFrame::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
    BOOL oldMin = m_isMinimum;
	switch(message)
	{
    case WM_SIZE:
        switch ( wParam ) {
        case SIZE_MINIMIZED:
            m_isMinimum = TRUE;
            break;
        case SIZE_MAXIMIZED:
        case SIZE_RESTORED:
            m_isMinimum = FALSE;
            break;
        }
        break;
	}

    if ( oldMin != m_isMinimum ) {
        if ( m_isMinimum ) {
            ShowTaskBarButton(FALSE);
            ShowWindow(SW_HIDE);
        }
    }
    return CLeashFrame::WindowProc(message, wParam, lParam);
}

/*
void CMainFrame::OnHelp()
{

}
*/

/*
void CMainFrame::OnContextHelp()
{

}
*/