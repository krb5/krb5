#ifdef _WIN32
#include <windows.h>

BOOL
WINAPI
DllMain(
    HANDLE hModule,
    DWORD fdwReason,
    LPVOID lpReserved
    )
{
    switch (fdwReason)
    {
	case DLL_PROCESS_ATTACH:
	    break;
	case DLL_THREAD_ATTACH:
	    break;
	case DLL_THREAD_DETACH:
	    break;
	case DLL_PROCESS_DETACH:
	    break;
	default:
	    return FALSE;
    }
    return TRUE;
}
#endif
