/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Copyright (2) 2007 Secure Endpoints Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#include<shlwapi.h>
#include<khmapp.h>
#include<netidmgr_intver.h>

/* used for the command-line help dialog */
#include<richedit.h>

#if DEBUG
#include<assert.h>

#if defined(KH_BUILD_PRIVATE) || defined(KH_BUILD_SPECIAL)
/* needed for writing out leaked allocation and handle report */
#include<stdio.h>
#endif

#endif

HINSTANCE khm_hInstance;
const wchar_t * khm_facility = L"NetIDMgr";
int khm_nCmdShow;
khm_ui_4 khm_commctl_version = 0;

khm_startup_options khm_startup;

const khm_version app_version = {KH_VERSION_LIST};

HRESULT hr_coinitialize = S_OK;

#if defined(DEBUG) && (defined(KH_BUILD_PRIVATE) || defined(KH_BUILD_SPECIAL))

KHMEXP void KHMAPI khcint_dump_handles(FILE * f);
KHMEXP void KHMAPI perf_dump(FILE * f);
KHMEXP void KHMAPI kmqint_dump(FILE * f);

#endif

void khm_init_gui(void) {

    hr_coinitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    khui_init_actions();
    khui_init_rescache();
    khui_init_menu();
    khui_init_toolbar();
    khm_init_notifier();
    khm_init_config();
    khm_init_debug();
    khm_init_taskbar_funcs();
}

void khm_exit_gui(void) {
    khm_exit_taskbar_funcs();
    khm_exit_debug();
    khm_exit_config();
    khm_exit_notifier();
    khui_exit_toolbar();
    khui_exit_menu();
    khui_exit_rescache();
    khui_exit_actions();

    if (hr_coinitialize == S_OK ||
        hr_coinitialize == S_FALSE) {
        CoUninitialize();
    }
}

/* This is passed into EnumResourceLanguages().  This returns the
   language ID of the first resource of the type and name that's
   passed into it.  For the resources types we care about, we only
   expect there to be one resource for a given name.  At the moment we
   don't support resource modules that contain resources for multiple
   languages. */
BOOL CALLBACK
khm_enum_res_lang_proc_first(HANDLE hModule,
                             LPCTSTR lpszType,
                             LPCTSTR lpszName,
                             WORD wIDLanguage,
                             LONG_PTR lParam)
{
    WORD * plangid = (WORD *) lParam;

    *plangid = wIDLanguage;

    return FALSE;
}

#define KHM_RTF_RESOURCE L"KHMRTFRESOURCE"

INT_PTR CALLBACK
khm_cmdline_dlg_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam)
{
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            WORD langID = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
            HRSRC h_resinfo = NULL;
            HGLOBAL h_resource = NULL;
            LPVOID h_resmem = NULL;
            SETTEXTEX ste;

            SetDlgItemText(hwnd, IDC_PRODUCT,
                           TEXT(KH_VERSTR_PRODUCT_1033));
#ifdef OVERRIDE_COPYRIGHT
            SetDlgItemText(hwnd, IDC_COPYRIGHT,
                           TEXT(KH_VERSTR_COPYRIGHT_1033));
#endif

            EnumResourceLanguages(khm_hInstance,
                                  KHM_RTF_RESOURCE,
                                  MAKEINTRESOURCE(IDR_CMDLINERTF),
                                  khm_enum_res_lang_proc_first,
                                  (LONG_PTR) &langID);

            h_resinfo = FindResourceEx(khm_hInstance,
                                       KHM_RTF_RESOURCE,
                                       MAKEINTRESOURCE(IDR_CMDLINERTF),
                                       langID);
            if (h_resinfo == NULL)
                goto init_failed;

            h_resource = LoadResource(khm_hInstance, h_resinfo);
            if (h_resinfo == NULL)
                goto init_failed;

            h_resmem = LockResource(h_resource);
            if (h_resmem == NULL)
                goto init_failed;

            ste.flags = ST_DEFAULT;
            ste.codepage = CP_ACP;

            SendDlgItemMessage(hwnd, IDC_CONTENT, EM_SETTEXTEX, (WPARAM) &ste, (LPARAM) h_resmem);
        init_failed:
            /* none of the above handles need to be freed. */

            return TRUE;
        }
        break;

    case WM_COMMAND:

        if (wParam == MAKEWPARAM(IDOK, BN_CLICKED)) {
            EndDialog(hwnd, KHM_ERROR_EXIT);
        }

        return TRUE;

    case WM_CLOSE:

	EndDialog(hwnd, KHM_ERROR_EXIT);

	return TRUE;
    }

    return FALSE;
}

void khm_show_commandline_help(void) {
    HMODULE hm_richedit;

    hm_richedit = LoadLibrary(L"riched20.dll");
    if (hm_richedit == NULL)
        return;

    DialogBox(khm_hInstance, MAKEINTRESOURCE(IDD_CMDLINE),
              NULL, khm_cmdline_dlg_proc);

    FreeLibrary(hm_richedit);
}

void khm_parse_commandline(void) {
    LPWSTR wcmdline;
    LPWSTR * wargs;
    int      wargc;
    int i;

    ZeroMemory(&khm_startup, sizeof(khm_startup));

    wcmdline = GetCommandLine();
    wargs = CommandLineToArgvW(wcmdline, &wargc);

    for (i=1; i<wargc; i++) {
        if (!wcscmp(wargs[i], L"-i") ||
            !wcscmp(wargs[i], L"--kinit") ||
            !wcscmp(wargs[i], L"-kinit")) {
            khm_startup.init = TRUE;
            khm_startup.exit = TRUE;
            khm_startup.no_main_window = TRUE;
            khm_startup.display |= SOPTS_DISPLAY_NODEF;
        }
        else if (!wcscmp(wargs[i], L"-m") ||
                 !wcscmp(wargs[i], L"--import") ||
                 !wcscmp(wargs[i], L"-import")) {
            khm_startup.import = TRUE;
            khm_startup.exit = TRUE;
            khm_startup.no_main_window = TRUE;
            khm_startup.display |= SOPTS_DISPLAY_NODEF;
        }
        else if (!wcscmp(wargs[i], L"-r") ||
                 !wcscmp(wargs[i], L"--renew") ||
                 !wcscmp(wargs[i], L"-renew")) {
            khm_startup.renew = TRUE;
            khm_startup.exit = TRUE;
            khm_startup.no_main_window = TRUE;
            khm_startup.display |= SOPTS_DISPLAY_NODEF;
        }
        else if (!wcscmp(wargs[i], L"-d") ||
                 !wcscmp(wargs[i], L"--destroy") ||
                 !wcscmp(wargs[i], L"-destroy")) {
            khm_startup.destroy = TRUE;
            khm_startup.exit = TRUE;
            khm_startup.no_main_window = TRUE;
            khm_startup.display |= SOPTS_DISPLAY_NODEF;
        }
        else if (!wcscmp(wargs[i], L"-a") ||
                 !wcscmp(wargs[i], L"--autoinit") ||
                 !wcscmp(wargs[i], L"-autoinit")) {
            khm_startup.autoinit = TRUE;
            khm_startup.display |= SOPTS_DISPLAY_NODEF;
        }
        else if (!wcscmp(wargs[i], L"-x") ||
                 !wcscmp(wargs[i], L"--exit") ||
                 !wcscmp(wargs[i], L"-exit")) {
            khm_startup.exit = TRUE;
            khm_startup.remote_exit = TRUE;
            khm_startup.no_main_window = TRUE;
            khm_startup.display |= SOPTS_DISPLAY_NODEF;
        }
        else if (!wcscmp(wargs[i], L"--minimized")) {
            khm_startup.no_main_window = TRUE;
            khm_startup.display |= SOPTS_DISPLAY_NODEF;
        }
        else if (!wcscmp(wargs[i], L"--show")) {
            if (khm_startup.display & SOPTS_DISPLAY_HIDE) {
                khm_show_commandline_help();
                khm_startup.error_exit = TRUE;
                break;
            }

            khm_startup.display |= (SOPTS_DISPLAY_SHOW | SOPTS_DISPLAY_NODEF);
        }
        else if (!wcscmp(wargs[i], L"--hide")) {
            if (khm_startup.display & SOPTS_DISPLAY_SHOW) {
                khm_show_commandline_help();
                khm_startup.error_exit = TRUE;
                break;
            }

            khm_startup.display |= (SOPTS_DISPLAY_HIDE | SOPTS_DISPLAY_NODEF);
            khm_startup.no_main_window = TRUE;
        }
        else {
            khm_show_commandline_help();

            khm_startup.error_exit = TRUE;
            break;
        }
    }

    /* special: always enable renew when other options aren't specified */
    if (!khm_startup.exit &&
        !khm_startup.destroy &&
        !khm_startup.init &&
        !khm_startup.remote_exit &&
        !khm_startup.display)
        khm_startup.renew = TRUE;
}

void khm_register_window_classes(void) {
    INITCOMMONCONTROLSEX ics;

    ZeroMemory(&ics, sizeof(ics));
    ics.dwSize = sizeof(ics);
    ics.dwICC =
        ICC_COOL_CLASSES |
        ICC_BAR_CLASSES |
        ICC_DATE_CLASSES |
        ICC_HOTKEY_CLASS |
        ICC_LISTVIEW_CLASSES |
        ICC_TAB_CLASSES |
        ICC_INTERNET_CLASSES |
#if (_WIN32_WINNT >= 0x501)
        ((IS_COMMCTL6())?
         ICC_LINK_CLASS |
         ICC_STANDARD_CLASSES :
         0) |
#endif
        0;

    InitCommonControlsEx(&ics);

    khm_register_main_wnd_class();
    khm_register_credwnd_class();
    khm_register_htwnd_class();
    khm_register_passwnd_class();
    khm_register_newcredwnd_class();
    khm_register_propertywnd_class();
}

void khm_unregister_window_classes(void) {
    khm_unregister_main_wnd_class();
    khm_unregister_credwnd_class();
    khm_unregister_htwnd_class();
    khm_unregister_passwnd_class();
    khm_unregister_newcredwnd_class();
    khm_unregister_propertywnd_class();
}


/* we support up to 16 simutaneous dialogs.  In reality, more than two
   is pretty unlikely.  Property sheets are special and are handled
   separately. */
#define MAX_UI_DIALOGS 16

typedef struct tag_khui_dialog {
    HWND hwnd;
    HWND hwnd_next;
    BOOL active;
} khui_dialog;

static khui_dialog khui_dialogs[MAX_UI_DIALOGS];
static int n_khui_dialogs = 0;
static HWND khui_modal_dialog = NULL;
static BOOL khui_main_window_active;

/* should only be called from the UI thread */
void khm_add_dialog(HWND dlg) {
    if(n_khui_dialogs < MAX_UI_DIALOGS - 1) {
        khui_dialogs[n_khui_dialogs].hwnd = dlg;
        khui_dialogs[n_khui_dialogs].hwnd_next = NULL;
        khui_dialogs[n_khui_dialogs].active = TRUE;
        n_khui_dialogs++;
    } else {
#if DEBUG
          assert(FALSE);
#endif
    }
}

/* should only be called from the UI thread */
void khm_enter_modal(HWND hwnd) {
    int i;

    if (khui_modal_dialog) {

        /* we are already in a modal loop. */

#ifdef DEBUG
        assert(hwnd != khui_modal_dialog);
#endif

        for (i=0; i < n_khui_dialogs; i++) {
            if (khui_dialogs[i].hwnd == khui_modal_dialog) {
                khui_dialogs[i].active = TRUE;
                EnableWindow(khui_modal_dialog, FALSE);
                break;
            }
        }

#ifdef DEBUG
        assert(i < n_khui_dialogs);
#endif

        for (i=0; i < n_khui_dialogs; i++) {
            if (khui_dialogs[i].hwnd == hwnd) {
                khui_dialogs[i].hwnd_next = khui_modal_dialog;
                break;
            }
        }

#ifdef DEBUG
        assert(i < n_khui_dialogs);
#endif

        khui_modal_dialog = hwnd;

    } else {

        /* we are entering a modal loop.  preserve the active state of
           the overlapped dialogs and proceed with the modal
           dialog. */

        for (i=0; i < n_khui_dialogs; i++) {
            if(khui_dialogs[i].hwnd != hwnd) {
                khui_dialogs[i].active = IsWindowEnabled(khui_dialogs[i].hwnd);
                EnableWindow(khui_dialogs[i].hwnd, FALSE);
            }
        }

        khui_main_window_active = khm_is_main_window_active();
        EnableWindow(khm_hwnd_main, FALSE);

        khui_modal_dialog = hwnd;

        SetForegroundWindow(hwnd);
    }
}

/* should only be called from the UI thread */
void khm_leave_modal(void) {
    int i;

    for (i=0; i < n_khui_dialogs; i++) {
        if (khui_dialogs[i].hwnd == khui_modal_dialog)
            break;
    }

#ifdef DEBUG
    assert(i < n_khui_dialogs);
#endif

    if (i < n_khui_dialogs && khui_dialogs[i].hwnd_next) {

        /* we need to proceed to the next one down the modal dialog
           chain.  We are not exiting a modal loop. */

        khui_modal_dialog = khui_dialogs[i].hwnd_next;
        khui_dialogs[i].hwnd_next = FALSE;

        EnableWindow(khui_modal_dialog, TRUE);

    } else {

        HWND last_dialog = NULL;

        /* we are exiting a modal loop. */

        for (i=0; i < n_khui_dialogs; i++) {
            if(khui_dialogs[i].hwnd != khui_modal_dialog) {
                EnableWindow(khui_dialogs[i].hwnd, khui_dialogs[i].active);
                last_dialog = khui_dialogs[i].hwnd;
            }
        }

        EnableWindow(khm_hwnd_main, TRUE);

        khui_modal_dialog = NULL;

        if(last_dialog)
            SetActiveWindow(last_dialog);
        else
            SetActiveWindow(khm_hwnd_main);
    }
}

/* should only be called from the UI thread */
void khm_del_dialog(HWND dlg) {
    int i;
    for(i=0;i < n_khui_dialogs; i++) {
        if(khui_dialogs[i].hwnd == dlg)
            break;
    }

    if(i < n_khui_dialogs)
        n_khui_dialogs--;
    else
        return;

    for(;i < n_khui_dialogs; i++) {
        khui_dialogs[i] = khui_dialogs[i+1];
    }
}

BOOL khm_check_dlg_message(LPMSG pmsg) {
    int i;
    BOOL found = FALSE;
    for(i=0;i<n_khui_dialogs;i++) {
        if(IsDialogMessage(khui_dialogs[i].hwnd, pmsg)) {
            found = TRUE;
            break;
        }
    }

    return found;
}

BOOL khm_is_dialog_active(void) {
    HWND hwnd;
    int i;

    hwnd = GetForegroundWindow();

    for (i=0; i<n_khui_dialogs; i++) {
        if (khui_dialogs[i].hwnd == hwnd)
            return TRUE;
    }

    return FALSE;
}

/* We support at most 256 property sheets simultaneously.  256
   property sheets should be enough for everybody. */
#define MAX_UI_PROPSHEETS 256

khui_property_sheet *_ui_propsheets[MAX_UI_PROPSHEETS];
int _n_ui_propsheets = 0;

void khm_add_property_sheet(khui_property_sheet * s) {
    if(_n_ui_propsheets < MAX_UI_PROPSHEETS)
        _ui_propsheets[_n_ui_propsheets++] = s;
    else {
#ifdef DEBUG
        assert(FALSE);
#endif
    }
}

void khm_del_property_sheet(khui_property_sheet * s) {
    int i;

    for(i=0;i < _n_ui_propsheets; i++) {
        if(_ui_propsheets[i] == s)
            break;
    }

    if(i < _n_ui_propsheets)
        _n_ui_propsheets--;
    else
        return;

    for(;i < _n_ui_propsheets; i++) {
        _ui_propsheets[i] = _ui_propsheets[i+1];
    }
}

BOOL khm_check_ps_message(LPMSG pmsg) {
    int i;
    khui_property_sheet * ps;
    for(i=0;i<_n_ui_propsheets;i++) {
        if(khui_ps_check_message(_ui_propsheets[i], pmsg)) {
            if(_ui_propsheets[i]->status == KHUI_PS_STATUS_DONE) {
                ps = _ui_propsheets[i];

                ps->status = KHUI_PS_STATUS_DESTROY;
                kmq_post_message(KMSG_CRED, KMSG_CRED_PP_END, 0, (void *) ps);

                return TRUE;
            }
            return TRUE;
        }
    }

    return FALSE;
}

static HACCEL ha_menu;

WPARAM khm_message_loop_int(khm_boolean * p_exit) {
    int r;
    MSG msg;

    while((r = GetMessage(&msg, NULL, 0,0)) &&
          (p_exit == NULL || *p_exit)) {
        if(r == -1)
            break;
        if(!khm_check_dlg_message(&msg) &&
           !khm_check_ps_message(&msg) &&
           !TranslateAccelerator(khm_hwnd_main, ha_menu, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return msg.wParam;
}

WPARAM khm_message_loop(void) {
    WPARAM w;
    ha_menu = khui_create_global_accel_table();
    w = khm_message_loop_int(NULL);
    DestroyAcceleratorTable(ha_menu);
    return w;
}

/* Handles all context closures which have a signalled error state.
   If the context is a top level context, then the errors are
   displayed. */
void KHMAPI
khm_err_ctx_completion_handler(enum kherr_ctx_event evt,
                               kherr_context * c) {
    kherr_event * e;
    khui_alert * a;

    /* we only handle top level contexts here.  For others, we allow
       the child contexts to fold upward silently. */
    if (c->parent || !kherr_is_error_i(c))
        return;

    for(e = kherr_get_first_event(c);
        e;
        e = kherr_get_next_event(e)) {

        if (e->severity != KHERR_ERROR && e->severity != KHERR_WARNING)
            continue;

        kherr_evaluate_event(e);

        /* we only report errors if there is enough information to
           present a message. */
        if (e->short_desc && e->long_desc) {

            khui_alert_create_empty(&a);

            khui_alert_set_severity(a, e->severity);
            khui_alert_set_title(a, e->short_desc);
            khui_alert_set_message(a, e->long_desc);
            if (e->suggestion)
                khui_alert_set_suggestion(a, e->suggestion);

            khui_alert_queue(a);

            khui_alert_release(a);
        }
    }
}

static wchar_t helpfile[MAX_PATH] = L"";

HWND khm_html_help(HWND hwnd, wchar_t * suffix,
                   UINT command, DWORD_PTR data) {

    wchar_t gpath[MAX_PATH + MAX_PATH];

    if (!*helpfile) {
        DWORD dw;
        wchar_t ppath[MAX_PATH];

        dw = GetModuleFileName(NULL, ppath, ARRAYLENGTH(ppath));

        if (dw == 0) {
            StringCbCopy(helpfile, sizeof(helpfile), NIDM_HELPFILE);
        } else {
            PathRemoveFileSpec(ppath);
            PathAppend(ppath, NIDM_HELPFILE);
            StringCbCopy(helpfile, sizeof(helpfile), ppath);
        }
    }

    StringCbCopy(gpath, sizeof(gpath), helpfile);

    if (suffix)
        StringCbCat(gpath, sizeof(gpath), suffix);

    return HtmlHelp(hwnd, gpath, command, data);
}

void khm_load_default_modules(void) {
    kmm_load_default_modules();
}

int khm_compare_version(const khm_version * v1, const khm_version * v2) {

    if (v1->major != v2->major)
        return ((int)v1->major) - ((int)v2->major);

    if (v1->minor != v2->minor)
        return ((int)v1->minor) - ((int)v2->minor);

    if (v1->patch != v2->patch)
        return ((int)v1->patch) - ((int)v2->patch);

    return ((int)v1->aux - ((int)v2->aux));
}

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine,
                   int nCmdShow)
{
    int rv = 0;
    HANDLE h_appmutex;
    BOOL slave = FALSE;
    int mutex_retries = 5;

    khm_hInstance = hInstance;
    khm_nCmdShow = nCmdShow;

    khm_parse_commandline();

    if (khm_startup.error_exit)
        return 0;

 _retry_mutex:

    if (--mutex_retries < 0)
        return 2;

    h_appmutex = CreateMutex(NULL, FALSE, L"Local\\NetIDMgr_GlobalAppMutex");
    if (h_appmutex == NULL)
        return 5;
    if (GetLastError() == ERROR_ALREADY_EXISTS)
        slave = TRUE;

    khc_load_schema(NULL, schema_uiconfig);

 _start_app:

    if(!slave) {

        PDESCTHREAD(L"UI", L"App");

        /* set this so that we don't accidently invoke an API that
           inadvertently puts up the new creds dialog at an
           inopportune moment, like, say, during the new creds dialog
           is open.  This only affects this process, and any child
           processes started by plugins. */
        SetEnvironmentVariable(L"KERBEROSLOGIN_NEVER_PROMPT", L"1");

        khm_version_init();

        khm_commctl_version = khm_get_commctl_version(NULL);

        /* we only open a main window if this is the only instance
           of the application that is running. */
        kmq_init();
        khm_init_gui();
        kmm_init();

        kmq_set_completion_handler(KMSG_CRED, kmsg_cred_completion);

        kherr_add_ctx_handler(khm_err_ctx_completion_handler,
                              KHERR_CTX_END,
                              0);

        /* load the standard plugins */
        khm_load_default_modules();

        khm_register_window_classes();

        khm_init_request_daemon();

        khm_create_main_window();

        if (!khm_startup.no_main_window &&
            nCmdShow != SW_SHOWMINNOACTIVE &&
            nCmdShow != SW_MINIMIZE &&
            nCmdShow != SW_SHOWMINIMIZED) {

            khm_show_main_window();
        }

        khm_refresh_config();

        rv = (int) khm_message_loop();

        kmq_set_completion_handler(KMSG_CRED, NULL);

        khm_exit_request_daemon();

        kmm_exit();
        khm_exit_gui();
        khm_unregister_window_classes();
        kmq_exit();

        CloseHandle(h_appmutex);
    } else {

        /* There is an instance of NetIDMgr already running. */

        HWND hwnd = NULL;
        int retries = 5;
        HANDLE hmap;
        wchar_t mapname[256];
        DWORD tid;
        void * xfer;
        khm_query_app_version query_app_version;
        khm_version v;
        BOOL use_cmd_v1 = FALSE;
        khm_size cb = 0;

        CloseHandle(h_appmutex);

        while (hwnd == NULL && retries) {
            hwnd = FindWindowEx(NULL, NULL, KHUI_MAIN_WINDOW_CLASS, NULL);

            if (hwnd)
                break;

            retries--;

            /* if the app was just starting, we might have to wait
               till the main window is created. */

            Sleep(1000);
        }

        if (!hwnd) {

            /* if the app was just exiting, we might see the mutex but
               not the window.  We go back and check if the mutex is
               still there. */

            goto _retry_mutex;
        }

        /* first check if the remote instance supports a version
           query */

        StringCbPrintf(mapname, sizeof(mapname),
                       QUERY_APP_VER_MAP_FMT,
                       (tid = GetCurrentThreadId()));

        hmap = CreateFileMapping(INVALID_HANDLE_VALUE,
                                 NULL,
                                 PAGE_READWRITE,
                                 0,
                                 4096,
                                 mapname);

        if (hmap == NULL)
            return 3;

        xfer = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0,
                             sizeof(query_app_version));

        ZeroMemory(&query_app_version, sizeof(query_app_version));

        if (xfer) {
            query_app_version.magic = KHM_QUERY_APP_VER_MAGIC;
            query_app_version.code = KHM_ERROR_NOT_IMPLEMENTED;
            query_app_version.ver_caller = app_version;

            query_app_version.request_swap = TRUE;

            memcpy(xfer, &query_app_version, sizeof(query_app_version));

            SendMessage(hwnd, WM_KHUI_QUERY_APP_VERSION,
                        0, (LPARAM) tid);

            memcpy(&query_app_version, xfer, sizeof(query_app_version));

            UnmapViewOfFile(xfer);
            xfer = NULL;
        }

        CloseHandle(hmap);
        hmap = NULL;

        if (query_app_version.magic != KHM_QUERY_APP_VER_MAGIC ||
            query_app_version.code != KHM_ERROR_SUCCESS) {

            /* We managed to communicate with the remote instance, but
               it didn't send us useful information.  The remote
               instance is not running an actual NetIDMgr instance.
               However, it owns a top level window that was registered
               with our classname.  This instance won't function
               properly if we let it proceed.
            */

            wchar_t error_msg[1024];
            wchar_t error_title[256];

            LoadString(khm_hInstance, IDS_REMOTE_FAIL_TITLE,
                       error_title, ARRAYLENGTH(error_title));
            LoadString(khm_hInstance, IDS_REMOTE_FAIL,
                       error_msg, ARRAYLENGTH(error_msg));

            MessageBox(NULL, error_msg, error_title,
                       MB_OK);

            goto done_with_remote;
        }

        if (query_app_version.code == KHM_ERROR_SUCCESS &&
            query_app_version.request_swap) {
            /* the request for swap was granted.  We can now
               initialize our instance as the master instance. */

            slave = FALSE;
            goto _start_app;
        }

        /* Now we can work on sending the command-line to the remote
           instance.  However we need to figure out which version of
           the startup structure it supports. */
        v.major = 1;
        v.minor = 2;
        v.patch = 0;
        v.aux = 0;

        if (khm_compare_version(&query_app_version.ver_remote, &app_version) == 0 ||
            khm_compare_version(&query_app_version.ver_remote, &v) > 0)
            use_cmd_v1 = FALSE;
        else
            use_cmd_v1 = TRUE;

        StringCbPrintf(mapname, sizeof(mapname),
                       COMMANDLINE_MAP_FMT,
                       (tid = GetCurrentThreadId()));

        cb = max(sizeof(khm_startup_options_v1),
                 sizeof(khm_startup_options_v2));

        cb = UBOUNDSS(cb, 4096, 4096);

#ifdef DEBUG
        assert(cb >= 4096);
#endif

        hmap = CreateFileMapping(INVALID_HANDLE_VALUE,
                                 NULL,
                                 PAGE_READWRITE,
                                 0,
                                 (DWORD) cb,
                                 mapname);

        if (hmap == NULL)
            return 3;

        /* make the call */

        if (!use_cmd_v1) {
            /* use the v2 structure */
            khm_startup_options_v3 opt;
            khm_startup_options_v3 *xferopt;

            ZeroMemory(&opt, sizeof(opt));

            opt.v2opt.magic = STARTUP_OPTIONS_MAGIC;

            opt.v2opt.init = khm_startup.init;
            opt.v2opt.import = khm_startup.import;
            opt.v2opt.renew = khm_startup.renew;
            opt.v2opt.destroy = khm_startup.destroy;
            opt.v2opt.autoinit = khm_startup.autoinit;
            opt.v2opt.remote_exit = khm_startup.remote_exit;
            opt.remote_display = khm_startup.display;

            opt.v2opt.code = KHM_ERROR_NOT_IMPLEMENTED;

            /* check if we can use the v3 options structure.  This
               should be possible for 1.3.1 and above. */
            v.major = 1; v.minor = 3; v.patch = 1; v.aux = 0;
            if (khm_compare_version(&query_app_version.ver_remote, &app_version) == 0 ||
                khm_compare_version(&query_app_version.ver_remote, &v) >= 0) {

                opt.v2opt.cb_size = sizeof(opt);

            } else {

                opt.v2opt.cb_size = sizeof(opt.v2opt);

            }

            xfer = MapViewOfFile(hmap,
                                 FILE_MAP_WRITE,
                                 0, 0,
                                 opt.v2opt.cb_size);

            xferopt = (khm_startup_options_v3 *) xfer;

            if (xfer) {
                memcpy(xfer, &opt, opt.v2opt.cb_size);

                SendMessage(hwnd, WM_KHUI_ASSIGN_COMMANDLINE_V2,
                            0, (LPARAM) tid);

                /* If it looks like the request was not processed, and
                   we were using a v3 request, fail-over to a v2
                   request. */
                if (xferopt->v2opt.code == KHM_ERROR_NOT_IMPLEMENTED &&
                    opt.v2opt.cb_size == sizeof(opt)) {

                    opt.v2opt.cb_size = sizeof(opt.v2opt);
                    memcpy(xfer, &opt, opt.v2opt.cb_size);

                    SendMessage(hwnd, WM_KHUI_ASSIGN_COMMANDLINE_V2,
                                0, (LPARAM) tid);
                }

                /* if it still looks like the request was not
                   processed, we failover to a v1 call */
                if (xferopt->v2opt.code == KHM_ERROR_NOT_IMPLEMENTED) {
                    use_cmd_v1 = TRUE;
                } else {
                    memcpy(&opt, xfer, opt.v2opt.cb_size);
                }

                UnmapViewOfFile(xfer);
                xfer = NULL;
            }
        }

        if (use_cmd_v1) {
            /* use the v1 structure */

            khm_startup_options_v1 v1opt;

            ZeroMemory(&v1opt, sizeof(v1opt));

            v1opt.init = khm_startup.init;
            v1opt.import = khm_startup.import;
            v1opt.renew = khm_startup.renew;
            v1opt.destroy = khm_startup.destroy;
            v1opt.autoinit = khm_startup.autoinit;

            xfer = MapViewOfFile(hmap,
                                 FILE_MAP_WRITE,
                                 0, 0,
                                 sizeof(v1opt));

            if (xfer) {
                memcpy(xfer, &v1opt, sizeof(v1opt));

                SendMessage(hwnd, WM_KHUI_ASSIGN_COMMANDLINE_V1,
                            0, (LPARAM) tid);

                UnmapViewOfFile(xfer);
                xfer = NULL;
            }
        }

    done_with_remote:

        if (hmap)
            CloseHandle(hmap);
    }

#if defined(DEBUG) && (defined(KH_BUILD_PRIVATE) || defined(KH_BUILD_SPECIAL))
    {
        FILE * f = NULL;

#if _MSC_VER >= 1400 && __STDC_WANT_SECURE_LIB__
        if (fopen_s(&f, "memleak.txt", "w") != 0)
            goto done_with_dump;
#else
        f = fopen("memleak.txt", "w");
        if (f == NULL)
            goto done_with_dump;
#endif

        perf_dump(f);
        khcint_dump_handles(f);
        kmqint_dump(f);

        fclose(f);

    done_with_dump:
        ;
    }
#endif

    return rv;
}
