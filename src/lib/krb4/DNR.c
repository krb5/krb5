/* 	DNR.c - DNR library for MPW

	(c) Copyright 1988 by Apple Computer.  All rights reserved
	
	Modifications by Jim Matthews, Dartmouth College, 5/91
	
	FIXME jcm - copied from Authman 1.0.7 release, file not in ftp.seeding.apple.com
	FIXME jcm -	slight improvments over the version in the KClient 1.1b1 release
	FIXME jcm - All rights reserved Apple Computer
*/

#include <OSUtils.h>
#include <Errors.h>
#include <Files.h>
#include <Resources.h>
#include <Memory.h>
#include <Traps.h>
#include <GestaltEqu.h>
#include <Folders.h>
#include <ToolUtils.h>

#define OPENRESOLVER	1L
#define CLOSERESOLVER	2L
#define STRTOADDR		3L
#define	ADDRTOSTR		4L
#define	ENUMCACHE		5L
#define ADDRTONAME		6L
#define	HINFO			7L
#define MXINFO			8L

Handle codeHndl = nil;

typedef OSErr (*OSErrProcPtr)(long,...);
OSErrProcPtr dnr = nil;


TrapType GetTrapType(theTrap)
unsigned long theTrap;
{
	if (BitAnd(theTrap, 0x0800) > 0)
		return(ToolTrap);
	else
		return(OSTrap);
	}
	
Boolean TrapAvailable(trap)
unsigned long trap;
{
TrapType trapType = ToolTrap;
unsigned long numToolBoxTraps;

	if (NGetTrapAddress(_InitGraf, ToolTrap) == NGetTrapAddress(0xAA6E, ToolTrap))
		numToolBoxTraps = 0x200;
	else
		numToolBoxTraps = 0x400;

	trapType = GetTrapType(trap);
	if (trapType == ToolTrap) {
		trap = BitAnd(trap, 0x07FF);
		if (trap >= numToolBoxTraps)
			trap = _Unimplemented;
		}
	return(NGetTrapAddress(trap, trapType) != NGetTrapAddress(_Unimplemented, ToolTrap));

}

void GetSystemFolder(short *vRefNumP, long *dirIDP)
{
	SysEnvRec info;
	long wdProcID;
	
	SysEnvirons(1, &info);
	if (GetWDInfo(info.sysVRefNum, vRefNumP, dirIDP, &wdProcID) != noErr) {
		*vRefNumP = 0;
		*dirIDP = 0;
		}
	}

void GetCPanelFolder(short *vRefNumP, long *dirIDP)
{
	Boolean hasFolderMgr = false;
	long feature;
	
/*
	if (TrapAvailable(_GestaltDispatch)) if (Gestalt(gestaltFindFolderAttr, &feature) == noErr) hasFolderMgr = true;
	
	FIXME jcm - what defines _Gestalt
	if (TrapAvailable(_Gestalt)) 
*/
	if (Gestalt(gestaltFindFolderAttr, &feature) == noErr) hasFolderMgr = true;
	if (!hasFolderMgr) {
		GetSystemFolder(vRefNumP, dirIDP);
		return;
		}
	else {
		if (FindFolder(kOnSystemDisk, kControlPanelFolderType, kDontCreateFolder, vRefNumP, dirIDP) != noErr) {
			*vRefNumP = 0;
			*dirIDP = 0;
			}
		}
	}
	
/* SearchFolderForDNRP is called to search a folder for files that might 
	contain the 'dnrp' resource */
short SearchFolderForDNRP(long targetType, long targetCreator, short vRefNum, long dirID)
{
	HParamBlockRec fi;
	Str255 filename;
	short refnum;
	
	fi.fileParam.ioCompletion = nil;
	fi.fileParam.ioNamePtr = filename;
	fi.fileParam.ioVRefNum = vRefNum;
	fi.fileParam.ioDirID = dirID;
	fi.fileParam.ioFDirIndex = 1;
	
	while (PBHGetFInfo(&fi, false) == noErr) {
		/* scan system folder for driver resource files of specific type & creator */
		if (fi.fileParam.ioFlFndrInfo.fdType == targetType &&
			fi.fileParam.ioFlFndrInfo.fdCreator == targetCreator) {
			/* found the MacTCP driver file? */
						
			refnum = HOpenResFile(vRefNum, dirID, filename, fsRdPerm);

			SetResLoad(false);
			if (GetIndResource('dnrp', 1) == NULL)	{
				SetResLoad(true);
				CloseResFile(refnum);
				}
			else	{
				SetResLoad(true);
				return refnum;
				}
			SetResLoad(true);
			}
		/* check next file in system folder */
		fi.fileParam.ioFDirIndex++;
		fi.fileParam.ioDirID = dirID;	/* PBHGetFInfo() clobbers ioDirID */
		}
	return(-1);
	}	

/* OpenOurRF is called to open the MacTCP driver resources */

short OpenOurRF()
{
	short refnum;
	short vRefNum;
	long dirID;
	
	/* first search Control Panels for MacTCP 1.1 */
	GetCPanelFolder(&vRefNum, &dirID);
	refnum = SearchFolderForDNRP('cdev', 'ztcp', vRefNum, dirID);
	if (refnum != -1) return(refnum);

	/* next search System Folder for MacTCP 1.0.x */
	GetSystemFolder(&vRefNum, &dirID);
	refnum = SearchFolderForDNRP('cdev', 'mtcp', vRefNum, dirID);
	if (refnum != -1) return(refnum);
		
	/* finally, search Control Panels for MacTCP 1.0.x */
	GetCPanelFolder(&vRefNum, &dirID);
	refnum = SearchFolderForDNRP('cdev', 'mtcp', vRefNum, dirID);
	if (refnum != -1) return(refnum);
		
	return -1;
	}	


OSErr OpenResolver(fileName)
char *fileName;
{
	short refnum;
	OSErr rc;
	
	if (dnr != nil)
		/* resolver already loaded in */
		return(noErr);
		
	/* open the MacTCP driver to get DNR resources. Search for it based on
	   creator & type rather than simply file name */	
	refnum = OpenOurRF();

	/* ignore failures since the resource may have been installed in the 
	   System file if running on a Mac 512Ke */
	   
	/* load in the DNR resource package */
	codeHndl = GetIndResource('dnrp', 1);
	if (codeHndl == nil) {
		/* can't open DNR */
		return(ResError());
		}
	
	DetachResource(codeHndl);
	if (refnum != -1) {
		CloseWD(refnum);
		CloseResFile(refnum);
		}
		
	/* lock the DNR resource since it cannot be reloated while opened */
	HLock(codeHndl);
	dnr = (OSErrProcPtr) *codeHndl;
	
	/* call open resolver */
	rc = (*dnr)(OPENRESOLVER, fileName);
	if (rc != noErr) {
		/* problem with open resolver, flush it */
		HUnlock(codeHndl);
		DisposHandle(codeHndl);
		dnr = nil;
		}
	return(rc);
	}


OSErr CloseResolver()
{
	if (dnr == nil)
		/* resolver not loaded error */
		return(notOpenErr);
		
	/* call close resolver */
	(void) (*dnr)(CLOSERESOLVER);

	/* release the DNR resource package */
	HUnlock(codeHndl);
	DisposHandle(codeHndl);
	dnr = nil;
	return(noErr);
	}

OSErr StrToAddr(hostName, rtnStruct, resultproc, userDataPtr)
char *hostName;
struct hostInfo *rtnStruct;
long resultproc;
char *userDataPtr;
{
	if (dnr == nil)
		/* resolver not loaded error */
		return(notOpenErr);
		
	return((*dnr)(STRTOADDR, hostName, rtnStruct, resultproc, userDataPtr));
	}
	
OSErr AddrToStr(addr, addrStr)
unsigned long addr;
char *addrStr;									
{
	if (dnr == nil)
		/* resolver not loaded error */
		return(notOpenErr);
		
	(*dnr)(ADDRTOSTR, addr, addrStr);
	return(noErr);
	}
	
OSErr EnumCache(resultproc, userDataPtr)
long resultproc;
char *userDataPtr;
{
	if (dnr == nil)
		/* resolver not loaded error */
		return(notOpenErr);
		
	return((*dnr)(ENUMCACHE, resultproc, userDataPtr));
	}
	
	
OSErr AddrToName(addr, rtnStruct, resultproc, userDataPtr)
unsigned long addr;
struct hostInfo *rtnStruct;
long resultproc;
char *userDataPtr;									
{
	if (dnr == nil)
		/* resolver not loaded error */
		return(notOpenErr);
		
	return((*dnr)(ADDRTONAME, addr, rtnStruct, resultproc, userDataPtr));
	}


extern OSErr HInfo(hostName, returnRecPtr, resultProc, userDataPtr)
char *hostName;
struct returnRec *returnRecPtr;
long resultProc;
char *userDataPtr;
{
	if (dnr == nil)
		/* resolver not loaded error */
		return(notOpenErr);
		
	return((*dnr)(HINFO, hostName, returnRecPtr, resultProc, userDataPtr));

	}
	
extern OSErr MXInfo(hostName, returnRecPtr, resultProc, userDataPtr)
char *hostName;
struct returnRec *returnRecPtr;
long resultProc;
char *userDataPtr;
{
	if (dnr == nil)
		/* resolver not loaded error */
		return(notOpenErr);
		
	return((*dnr)(MXINFO, hostName, returnRecPtr, resultProc, userDataPtr));

	}
