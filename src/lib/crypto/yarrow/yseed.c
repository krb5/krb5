/* -*- Mode: C; c-file-style: "bsd" -*- */
/*
 * Yarrow - Cryptographic Pseudo-Random Number Generator
 * Copyright (c) 2000 Zero-Knowledge Systems, Inc.
 *
 * See the accompanying LICENSE file for license information.
 */

#ifdef WIN32
# ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0400 /* for wincrypt.h */
# endif
# include <windows.h>
# include <wincrypt.h>
# include <tlhelp32.h>
#endif

#include "yarrow.h"
#include "yexcep.h"

#ifdef WIN32
/* Intel hardware RNG CSP -- available from
 * http://developer.intel.com/design/security/rng/redist_license.htm
 */
# define PROV_INTEL_SEC 22
# define INTEL_DEF_PROV "Intel Hardware Cryptographic Service Provider"

typedef BOOL (WINAPI *CRYPTACQUIRECONTEXT)(HCRYPTPROV *, LPCTSTR, LPCTSTR,
					   DWORD, DWORD);
typedef BOOL (WINAPI *CRYPTGENRANDOM)(HCRYPTPROV, DWORD, BYTE *);
typedef BOOL (WINAPI *CRYPTRELEASECONTEXT)(HCRYPTPROV, DWORD);

typedef HWND (WINAPI *GETFOREGROUNDWINDOW)(VOID);
typedef BOOL (WINAPI *GETCURSORINFO)(PCURSORINFO);
typedef DWORD (WINAPI *GETQUEUESTATUS)(UINT);

typedef HANDLE (WINAPI *CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef BOOL (WINAPI *HEAP32FIRST)(LPHEAPENTRY32, DWORD, DWORD);
typedef BOOL (WINAPI *HEAP32NEXT)(LPHEAPENTRY32);
typedef BOOL (WINAPI *HEAP32LIST)(HANDLE, LPHEAPLIST32);
typedef BOOL (WINAPI *PROCESS32)(HANDLE, LPPROCESSENTRY32);
typedef BOOL (WINAPI *THREAD32)(HANDLE, LPTHREADENTRY32);
typedef BOOL (WINAPI *MODULE32)(HANDLE, LPMODULEENTRY32);

#define RAND_add(sample, size, entropy_bytes) \
  Yarrow_Input(y, (source_id), (sample), (size), 8*(entropy_bytes))

#include "yarrow.h"

static void readtimer(Yarrow_CTX *, unsigned);

int Yarrow_Poll(Yarrow_CTX *y, unsigned source_id)
{
    EXCEP_DECL;
    MEMORYSTATUS m;
    HCRYPTPROV hProvider = 0;
    BYTE buf[64];
    DWORD w;
    HWND h;

    HMODULE advapi, kernel, user;
    CRYPTACQUIRECONTEXT acquire;
    CRYPTGENRANDOM gen;
    CRYPTRELEASECONTEXT release;

    /* load functions dynamically - not available on all systems */
    advapi = GetModuleHandle("ADVAPI32.DLL");
    kernel = GetModuleHandle("KERNEL32.DLL");
    user = GetModuleHandle("USER32.DLL");
  
    if (advapi)
    {
	acquire = (CRYPTACQUIRECONTEXT) GetProcAddress(advapi,
						       "CryptAcquireContextA");
	gen = (CRYPTGENRANDOM) GetProcAddress(advapi,
					      "CryptGenRandom");
	release = (CRYPTRELEASECONTEXT) GetProcAddress(advapi,
						       "CryptReleaseContext");
    }
  
    if (acquire && gen && release)
    {
	/* poll the CryptoAPI PRNG */
	if (acquire(&hProvider, 0, 0, PROV_RSA_FULL,
		    CRYPT_VERIFYCONTEXT))
	{
	    if (gen(hProvider, sizeof(buf), buf) != 0)
	    {
		RAND_add(buf, sizeof(buf), 0);
# ifdef DEBUG
		printf("randomness from PROV_RSA_FULL\n");
# endif
	    }
	    release(hProvider, 0); 
	}
      
	/* poll the Pentium PRG with CryptoAPI */
	if (acquire(&hProvider, 0, INTEL_DEF_PROV, PROV_INTEL_SEC, 0))
	{
	    if (gen(hProvider, sizeof(buf), buf) != 0)
	    {
		RAND_add(buf, sizeof(buf), 0);
# ifdef DEBUG
		printf("randomness from PROV_INTEL_SEC\n");
# endif
	    }
	    release(hProvider, 0);
	}
    }
  
    /* timer data */
    readtimer(y, source_id);
  
    /* memory usage statistics */
    GlobalMemoryStatus(&m);
    RAND_add(&m, sizeof(m), 1);
  
    /* process ID */
    w = GetCurrentProcessId();
    RAND_add(&w, sizeof(w), 0);
  
    if (user)
    {
	GETCURSORINFO cursor;
	GETFOREGROUNDWINDOW win;
	GETQUEUESTATUS queue;
    
	win = (GETFOREGROUNDWINDOW) GetProcAddress(user, "GetForegroundWindow");
	cursor = (GETCURSORINFO) GetProcAddress(user, "GetCursorInfo");
	queue = (GETQUEUESTATUS) GetProcAddress(user, "GetQueueStatus");
    
	if (win)
	{
	    /* window handle */
	    h = win();
	    RAND_add(&h, sizeof(h), 0);
	}
      
	if (cursor)
	{
	    /* cursor position */
	    cursor(buf);
	    RAND_add(buf, sizeof(buf), 0);
	}
      
	if (queue)
	{
	    /* message queue status */
	    w = queue(QS_ALLEVENTS);
	    RAND_add(&w, sizeof(w), 0);
	}
    }
  
    /* Toolhelp32 snapshot: enumerate processes, threads, modules and heap
     * http://msdn.microsoft.com/library/psdk/winbase/toolhelp_5pfd.htm
     * (Win 9x only, not available on NT)
     *
     * This seeding method was proposed in Peter Gutmann, Software
     * Generation of Practically Strong Random Numbers,
     * http://www.cs.auckland.ac.nz/~pgut001/pubs/random2.pdf
     * (The assignment of entropy estimates below is arbitrary, but based
     * on Peter's analysis the full poll appears to be safe. Additional
     * interactive seeding is encouraged.)
     */

    if (kernel)
    {
	CREATETOOLHELP32SNAPSHOT snap;
	HANDLE handle;
    
	HEAP32FIRST heap_first;
	HEAP32NEXT heap_next;
	HEAP32LIST heaplist_first, heaplist_next;
	PROCESS32 process_first, process_next;
	THREAD32 thread_first, thread_next;
	MODULE32 module_first, module_next;

	HEAPLIST32 hlist;
	HEAPENTRY32 hentry;
	PROCESSENTRY32 p;
	THREADENTRY32 t;
	MODULEENTRY32 m;
    
	snap = (CREATETOOLHELP32SNAPSHOT)
	    GetProcAddress(kernel, "CreateToolhelp32Snapshot");
	heap_first = (HEAP32FIRST) GetProcAddress(kernel, "Heap32First");
	heap_next = (HEAP32NEXT) GetProcAddress(kernel, "Heap32Next");
	heaplist_first = (HEAP32LIST) GetProcAddress(kernel, "Heap32ListFirst");
	heaplist_next = (HEAP32LIST) GetProcAddress(kernel, "Heap32ListNext");
	process_first = (PROCESS32) GetProcAddress(kernel, "Process32First");
	process_next = (PROCESS32) GetProcAddress(kernel, "Process32Next");
	thread_first = (THREAD32) GetProcAddress(kernel, "Thread32First");
	thread_next = (THREAD32) GetProcAddress(kernel, "Thread32Next");
	module_first = (MODULE32) GetProcAddress(kernel, "Module32First");
	module_next = (MODULE32) GetProcAddress(kernel, "Module32Next");

	if (snap && heap_first && heap_next && heaplist_first &&
	    heaplist_next && process_first && process_next &&
	    thread_first && thread_next && module_first &&
	    module_next && (handle = snap(TH32CS_SNAPALL,0)) != NULL)
	{
	    /* heap list and heap walking */
	    hlist.dwSize = sizeof(HEAPLIST32);		
	    if (heaplist_first(handle, &hlist))
		do
		{
		    RAND_add(&hlist, hlist.dwSize, 0);
		    hentry.dwSize = sizeof(HEAPENTRY32);
		    if (heap_first(&hentry,
				   hlist.th32ProcessID,
				   hlist.th32HeapID))
			do
			    RAND_add(&hentry,
				     hentry.dwSize, 0);
			while (heap_next(&hentry));
		} while (heaplist_next(handle,
				       &hlist));
      
	    /* process walking */
	    p.dwSize = sizeof(PROCESSENTRY32);
	    if (process_first(handle, &p))
		do
		    RAND_add(&p, p.dwSize, 0);
		while (process_next(handle, &p));
      
	    /* thread walking */
	    t.dwSize = sizeof(THREADENTRY32);
	    if (thread_first(handle, &t))
		do
		    RAND_add(&t, t.dwSize, 0);
		while (thread_next(handle, &t));
      
	    /* module walking */
	    m.dwSize = sizeof(MODULEENTRY32);
	    if (module_first(handle, &m))
		do
		    RAND_add(&m, m.dwSize, 1);
		while (module_next(handle, &m));
      
	    CloseHandle(handle);
	}
    }
    TRY( Yarrow_Status( y, NULL, NULL, NULL, NULL ) );
 CATCH:
    EXCEP_RET;
}

/* feed timing information to the PRNG */
static void readtimer(Yarrow_CTX *y, unsigned source_id)
{
    DWORD w, cyclecount;
    LARGE_INTEGER l;
    static int have_perfc = 1;
#ifndef __GNUC__
    static int have_tsc = 1;

    if (have_tsc) {
	__try {
	    __asm {
		rdtsc
		    mov cyclecount, eax
		    }
	    RAND_add(&cyclecount, sizeof(cyclecount), 1);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    have_tsc = 0;
	}
    }
#else
# define have_tsc 0
#endif

    if (have_perfc) {
	if (QueryPerformanceCounter(&l) == 0)
	{
	    have_perfc = 0;
	}
	else
	{
	    RAND_add(&l, sizeof(l), 0);
	}
    }

    if (!have_tsc && !have_perfc) {
	w = GetTickCount();
	RAND_add(&w, sizeof(w), 0);
    }
}

#else

int Yarrow_Poll(Yarrow_CTX *y, unsigned source_id)
{
    source_id = source_id;
    return Yarrow_Status( y, NULL, NULL, NULL, NULL );
}

#endif
