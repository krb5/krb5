;-----------------------------------------------------------------
; KfW defines and functionality
; Copyright (c) 2004 Massachusetts Institute of Technology

!define KFW_VERSION "${KFW_MAJORVERSION}.${KFW_MINORVERSION}.${KFW_PATCHLEVEL}"

!define PROGRAM_NAME "Kerberos for Windows"
!ifdef RELEASE
!ifndef DEBUG        ; !DEBUG on v2.0b4
Name "MIT ${PROGRAM_NAME} ${KFW_VERSION}"
!else                ; DEBUG on v2.0b4
Name "MIT ${PROGRAM_NAME} ${KFW_VERSION} Checked/Debug"
!endif               ; End DEBUG/!DEBUG
!else
!ifdef BETA
!ifndef DEBUG        ; !DEBUG on v2.0b4
Name "MIT ${PROGRAM_NAME} ${KFW_VERSION} Beta ${BETA}"
!else                ; DEBUG on v2.0b4
Name "MIT ${PROGRAM_NAME} ${KFW_VERSION} Beta ${BETA} Checked/Debug"
!endif               ; End DEBUG/!DEBUG
!else
!ifndef DEBUG        ; !DEBUG on v2.0b4
Name "MIT ${PROGRAM_NAME} ${KFW_VERSION} ${__DATE__} ${__TIME__}"
!else                ; DEBUG on v2.0b4
Name "MIT ${PROGRAM_NAME} ${KFW_VERSION} ${__DATE__} ${__TIME__} Checked/Debug"
!endif               ; End DEBUG/!DEBUG
!endif
!endif
VIProductVersion "${KFW_MAJORVERSION}.${KFW_MINORVERSION}.${KFW_PATCHLEVEL}.00"
VIAddVersionKey "ProductName" "${PROGRAM_NAME}"
VIAddVersionKey "CompanyName" "Massachusetts Institute of Technology"
VIAddVersionKey "ProductVersion" ${VIProductVersion}
VIAddVersionKey "FileVersion" ${VIProductVersion}
VIAddVersionKey "FileDescription" "MIT Kerberos for Windows Installer"
VIAddVersionKey "LegalCopyright" "(C)2004"
!ifdef DEBUG
VIAddVersionKey "PrivateBuild" "Checked/Debug"
!endif               ; End DEBUG


;--------------------------------
;Configuration

  ;General
  SetCompressor lzma
!ifndef DEBUG
  OutFile "MITKerberosForWindows.exe"
!else
  OutFile "MITKerberosForWindows-DEBUG.exe"
!endif
  SilentInstall normal
  ShowInstDetails show
  XPStyle on
  !define MUI_ICON "kfw.ico"
  !define MUI_UNICON "kfw.ico"
  !define KFW_COMPANY_NAME "Massachusetts Institute of Technology"
  !define KFW_PRODUCT_NAME "${PROGRAM_NAME}"
  !define KFW_REGKEY_ROOT  "Software\MIT\Kerberos\"
  CRCCheck force
  !define REPLACEDLL_NOREGISTER

  ;Folder selection page
  InstallDir "$PROGRAMFILES\MIT\Kerberos"      ; Install to shorter path
  
  ;Remember install folder
  InstallDirRegKey HKLM "${KFW_REGKEY_ROOT}" ""
  
  ;Remember the installer language
  !define MUI_LANGDLL_REGISTRY_ROOT "HKLM" 
  !define MUI_LANGDLL_REGISTRY_KEY "${KFW_REGKEY_ROOT}" 
  !define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"
  
  ;Where are the files?
  !define KFW_BIN_DIR "${KFW_TARGETDIR}\bin\i386"
  !define KFW_DOC_DIR "${KFW_TARGETDIR}\doc"
  !define KFW_INC_DIR "${KFW_TARGETDIR}\inc"
  !define KFW_LIB_DIR "${KFW_TARGETDIR}\lib\i386"
  !define KFW_INSTALL_DIR "${KFW_TARGETDIR}\install"
  !define SYSTEMDIR   "$%SystemRoot%\System32" 
 

;--------------------------------
;Modern UI Configuration

  !define MUI_LICENSEPAGE
  !define MUI_CUSTOMPAGECOMMANDS
  !define MUI_WELCOMEPAGE
  !define MUI_COMPONENTSPAGE
  !define MUI_COMPONENTSPAGE_SMALLDESC
  !define MUI_DIRECTORYPAGE

  !define MUI_ABORTWARNING
  !define MUI_FINISHPAGE
  
  !define MUI_UNINSTALLER
  !define MUI_UNCONFIRMPAGE
  
  
  !insertmacro MUI_PAGE_WELCOME
  !insertmacro MUI_PAGE_LICENSE "Licenses.rtf"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  Page custom KFWPageGetConfigFiles
  Page custom KFWPageGetStartupConfig
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH
  
;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"
  
;--------------------------------
;Language Strings
    
  ;Descriptions
  LangString DESC_SecCopyUI ${LANG_ENGLISH} "${PROGRAM_NAME}: English"

  LangString DESC_secClient ${LANG_ENGLISH} "Client: Allows you to utilize MIT Kerberos from your Windows PC."
  
  LangString DESC_secSDK ${LANG_ENGLISH} "SDK: Allows you to build MIT Kerberos aware applications."
  
  LangString DESC_secDocs ${LANG_ENGLISH} "Documentation: Release Notes and User Manuals."
  
; Popup error messages
  LangString RealmNameError ${LANG_ENGLISH} "You must specify a realm name for your client to use."

  LangString ConfigFileError ${LANG_ENGLISH} "You must specify a valid configuration file location from which files can be copied during the install"
 
  LangString URLError ${LANG_ENGLISH} "You must specify a URL if you choose the option to download the config files."
  
; Upgrade/re-install strings
   LangString UPGRADE_CLIENT ${LANG_ENGLISH} "Upgrade Kerberos Client"
   LangString REINSTALL_CLIENT ${LANG_ENGLISH} "Re-install Kerberos Client"
   LangString DOWNGRADE_CLIENT ${LANG_ENGLISH} "Downgrade Kerberos Client"
  
   LangString UPGRADE_SDK ${LANG_ENGLISH} "Upgrade Kerberos SDK"
   LangString REINSTALL_SDK ${LANG_ENGLISH} "Re-install Kerberos SDK"
   LangString DOWNGRADE_SDK ${LANG_ENGLISH} "Downgrade Kerberos SDK"
  
   LangString UPGRADE_DOCS ${LANG_ENGLISH} "Upgrade Kerberos Documentation"
   LangString REINSTALL_DOCS ${LANG_ENGLISH} "Re-install Kerberos Documentation"
   LangString DOWNGRADE_DOCS ${LANG_ENGLISH} "Downgrade Kerberos Documentation"
  
  ReserveFile "${KFW_CONFIG_DIR}\krb.con"
  ReserveFile "${KFW_CONFIG_DIR}\krbrealm.con"
  ReserveFile "${KFW_CONFIG_DIR}\krb5.ini"
  !insertmacro MUI_RESERVEFILE_INSTALLOPTIONS ;InstallOptions plug-in
  !insertmacro MUI_RESERVEFILE_LANGDLL ;Language selection dialog

;--------------------------------
;Reserve Files
  
  ;Things that need to be extracted on first (keep these lines before any File command!)
  ;Only useful for BZIP2 compression
  !insertmacro MUI_RESERVEFILE_LANGDLL
  
;--------------------------------
; Load Macros
!include "utils.nsi"

;--------------------------------
;Installer Sections

;----------------------
; Kerberos for Windows CLIENT
Section "KfW Client" secClient

  SetShellVarContext all
  ; Stop any running services or we can't replace the files
  ; Stop the running processes
  GetTempFileName $R0
  File /oname=$R0 "Killer.exe"
  nsExec::Exec '$R0 leash32.exe'
  nsExec::Exec '$R0 krbcc32s.exe'
  nsExec::Exec '$R0 k95.exe'
  nsExec::Exec '$R0 k95g.exe'
  nsExec::Exec '$R0 krb5.exe'
  nsExec::Exec '$R0 gss.exe'
  nsExec::Exec '$R0 afscreds.exe'

  RMDir /r "$INSTDIR\bin"

   ; Do client components
  SetOutPath "$INSTDIR\bin"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\aklog.exe"           "$INSTDIR\bin\aklog.exe"         "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\comerr32.dll"        "$INSTDIR\bin\comerr32.dll"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\gss.exe"             "$INSTDIR\bin\gss.exe"           "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\gss-client.exe"      "$INSTDIR\bin\gss-client.exe"    "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\gss-server.exe"      "$INSTDIR\bin\gss-server.exe"    "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\gssapi32.dll"        "$INSTDIR\bin\gssapi32.dll"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\k524init.exe"        "$INSTDIR\bin\k524init.exe"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\kclnt32.dll"         "$INSTDIR\bin\kclnt32.dll"       "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\kdestroy.exe"        "$INSTDIR\bin\kdestroy.exe"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\kinit.exe"           "$INSTDIR\bin\kinit.exe"         "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\klist.exe"           "$INSTDIR\bin\klist.exe"         "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\kpasswd.exe"         "$INSTDIR\bin\kpasswd.exe"       "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\kvno.exe"            "$INSTDIR\bin\kvno.exe"          "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\krb5_32.dll"         "$INSTDIR\bin\krb5_32.dll"       "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\krb524.dll"          "$INSTDIR\bin\krb524.dll"        "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\krbcc32.dll"         "$INSTDIR\bin\krbcc32.dll"       "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\krbcc32s.exe"        "$INSTDIR\bin\krbcc32s.exe"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\krbv4w32.dll"        "$INSTDIR\bin\krbv4w32.dll"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\leash32.exe"         "$INSTDIR\bin\leash32.exe"       "$INSTDIR"
!ifdef OLDHELP                                                                 
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\leash32.hlp"         "$INSTDIR\bin\leash32.hlp"       "$INSTDIR"
!else                                                                          
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\leash32.chm"         "$INSTDIR\bin\leash32.chm"       "$INSTDIR"
!endif                                                                         
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\leashw32.dll"        "$INSTDIR\bin\leashw32.dll"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\ms2mit.exe"          "$INSTDIR\bin\ms2mit.exe"        "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\wshelp32.dll"        "$INSTDIR\bin\wshelp32.dll"      "$INSTDIR"
  !insertmacro ReplaceDLL "${KFW_BIN_DIR}\xpprof32.dll"        "$INSTDIR\bin\xpprof32.dll"      "$INSTDIR"
  
!ifdef DEBUG
  File "${KFW_BIN_DIR}\aklog.pdb"
  File "${KFW_BIN_DIR}\comerr32.pdb"
  File "${KFW_BIN_DIR}\gss.pdb"
  File "${KFW_BIN_DIR}\gss-client.pdb"
  File "${KFW_BIN_DIR}\gss-server.pdb"
  File "${KFW_BIN_DIR}\gssapi32.pdb"
  File "${KFW_BIN_DIR}\k524init.pdb"
  File "${KFW_BIN_DIR}\kclnt32.pdb"
  File "${KFW_BIN_DIR}\kdestroy.pdb"
  File "${KFW_BIN_DIR}\kinit.pdb"
  File "${KFW_BIN_DIR}\klist.pdb"
  File "${KFW_BIN_DIR}\kpasswd.pdb"
  File "${KFW_BIN_DIR}\kvno.pdb"
  File "${KFW_BIN_DIR}\krb5_32.pdb"
  File "${KFW_BIN_DIR}\krb524.pdb"
  File "${KFW_BIN_DIR}\krbcc32.pdb"
  File "${KFW_BIN_DIR}\krbcc32s.pdb"
  File "${KFW_BIN_DIR}\krbv4w32.pdb"
  File "${KFW_BIN_DIR}\leashw32.pdb"
  File "${KFW_BIN_DIR}\leash32.pdb"
  File "${KFW_BIN_DIR}\ms2mit.pdb"
  File "${KFW_BIN_DIR}\wshelp32.pdb"
  File "${KFW_BIN_DIR}\xpprof32.pdb"

!IFDEF CL_1310
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcr71d.dll"    "$INSTDIR\bin\msvcr71d.dll"  "$INSTDIR"
  File "${SYSTEMDIR}\msvcr71d.pdb"                                           
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcp71d.dll"    "$INSTDIR\bin\msvcp71d.dll"  "$INSTDIR"
  File "${SYSTEMDIR}\msvcp71d.pdb"                                           
  !insertmacro ReplaceDLL "${SYSTEMDIR}\mfc71d.dll"      "$INSTDIR\bin\mfc71d.dll"    "$INSTDIR"
  File "${SYSTEMDIR}\mfc71d.pdb"                                             
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71CHS.DLL"    "$INSTDIR\bin\MFC71CHS.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71CHT.DLL"    "$INSTDIR\bin\MFC71CHT.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71DEU.DLL"    "$INSTDIR\bin\MFC71DEU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71ENU.DLL"    "$INSTDIR\bin\MFC71ENU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71ESP.DLL"    "$INSTDIR\bin\MFC71ESP.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71FRA.DLL"    "$INSTDIR\bin\MFC71FRA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71ITA.DLL"    "$INSTDIR\bin\MFC71ITA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71JPN.DLL"    "$INSTDIR\bin\MFC71JPN.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71KOR.DLL"    "$INSTDIR\bin\MFC71KOR.DLL"  "$INSTDIR"
!ELSE                                                                   
!IFDEF CL_1300                                                          
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcr70d.dll"    "$INSTDIR\bin\msvcr70d.dll"  "$INSTDIR"
  File "${SYSTEMDIR}\msvcr70d.pdb"                                           
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcp70d.dll"    "$INSTDIR\bin\msvcp70d.dll"  "$INSTDIR"
  File "${SYSTEMDIR}\msvcp70d.pdb"                                           
  !insertmacro ReplaceDLL "${SYSTEMDIR}\mfc70d.dll"      "$INSTDIR\bin\mfc70d.dll"    "$INSTDIR"
  File "${SYSTEMDIR}\mfc70d.pdb"                                             
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70CHS.DLL"    "$INSTDIR\bin\MFC70CHS.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70CHT.DLL"    "$INSTDIR\bin\MFC70CHT.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70DEU.DLL"    "$INSTDIR\bin\MFC70DEU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70ENU.DLL"    "$INSTDIR\bin\MFC70ENU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70ESP.DLL"    "$INSTDIR\bin\MFC70ESP.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70FRA.DLL"    "$INSTDIR\bin\MFC70FRA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70ITA.DLL"    "$INSTDIR\bin\MFC70ITA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70JPN.DLL"    "$INSTDIR\bin\MFC70JPN.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70KOR.DLL"    "$INSTDIR\bin\MFC70KOR.DLL"  "$INSTDIR"
!ELSE                                                                   
  !insertmacro ReplaceDLL "${SYSTEMDIR}\mfc42d.dll"      "$INSTDIR\bin\mfc42d.dll"    "$INSTDIR"
  File "${SYSTEMDIR}\mfc42d.pdb"                                             
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcp60d.dll"    "$INSTDIR\bin\msvcp60d.dll"  "$INSTDIR"
  File "${SYSTEMDIR}\msvcp60d.pdb"                                           
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcrtd.dll"     "$INSTDIR\bin\msvcrtd.dll"   "$INSTDIR"
  File "${SYSTEMDIR}\msvcrtd.pdb"                                            
!ENDIF                                                                  
!ENDIF                                                                  
!ELSE                                                                   
!IFDEF CL_1310                                                          
  !insertmacro ReplaceDLL "${SYSTEMDIR}\mfc71.dll"       "$INSTDIR\bin\mfc71.dll"     "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcr71.dll"     "$INSTDIR\bin\msvcr71.dll"   "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcp71.dll"     "$INSTDIR\bin\msvcp71.dll"   "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71CHS.DLL"    "$INSTDIR\bin\MFC71CHS.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71CHT.DLL"    "$INSTDIR\bin\MFC71CHT.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71DEU.DLL"    "$INSTDIR\bin\MFC71DEU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71ENU.DLL"    "$INSTDIR\bin\MFC71ENU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71ESP.DLL"    "$INSTDIR\bin\MFC71ESP.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71FRA.DLL"    "$INSTDIR\bin\MFC71FRA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71ITA.DLL"    "$INSTDIR\bin\MFC71ITA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71JPN.DLL"    "$INSTDIR\bin\MFC71JPN.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC71KOR.DLL"    "$INSTDIR\bin\MFC71KOR.DLL"  "$INSTDIR"
!ELSE                                                                   
!IFDEF CL_1300                                                          
  !insertmacro ReplaceDLL "${SYSTEMDIR}\mfc70.dll"       "$INSTDIR\bin\mfc70.dll"     "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcr70.dll"     "$INSTDIR\bin\msvcr70.dll"   "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcp70.dll"     "$INSTDIR\bin\msvcp70.dll"   "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70CHS.DLL"    "$INSTDIR\bin\MFC70CHS.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70CHT.DLL"    "$INSTDIR\bin\MFC70CHT.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70DEU.DLL"    "$INSTDIR\bin\MFC70DEU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70ENU.DLL"    "$INSTDIR\bin\MFC70ENU.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70ESP.DLL"    "$INSTDIR\bin\MFC70ESP.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70FRA.DLL"    "$INSTDIR\bin\MFC70FRA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70ITA.DLL"    "$INSTDIR\bin\MFC70ITA.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70JPN.DLL"    "$INSTDIR\bin\MFC70JPN.DLL"  "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\MFC70KOR.DLL"    "$INSTDIR\bin\MFC70KOR.DLL"  "$INSTDIR"
!ELSE                                                                   
  !insertmacro ReplaceDLL "${SYSTEMDIR}\mfc42.dll"       "$INSTDIR\bin\mfc42.dll"     "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcp60.dll"     "$INSTDIR\bin\msvcp60.dll"   "$INSTDIR"
  !insertmacro ReplaceDLL "${SYSTEMDIR}\msvcrt.dll"      "$INSTDIR\bin\msvcrt.dll"    "$INSTDIR"
!ENDIF                                                                  
!ENDIF                                                                  
!ENDIF                                                                  
  !insertmacro ReplaceDLL "${SYSTEMDIR}\psapi.dll"       "$INSTDIR\bin\psapi.dll"     "$INSTDIR"
   
  ; Do WINDOWSDIR components
  ;SetOutPath "$WINDOWSDIR"
!ifdef DEBUG
!endif
  
  ; Do Windows SYSDIR (Control panel)
  ;SetOutPath "$SYSDIR"
!ifdef DEBUG
!endif
  
  ; Get Kerberos config files
  Call kfw.GetConfigFiles

  Call KFWCommon.Install
  
  ; KfW Reg entries
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "VersionString" ${KFW_VERSION}
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "Title" "KfW"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "Description" "${PROGRAM_NAME}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "PathName" "$INSTDIR"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "Software Type" "Authentication"
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "MajorVersion" ${KFW_MAJORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "MinorVersion" ${KFW_MINORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "PatchLevel" ${KFW_PATCHLEVEL}

  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "VersionString" ${KFW_VERSION}
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "Title" "KfW"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "Description" "${PROGRAM_NAME}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "PathName" "$INSTDIR"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "Software Type" "Authentication"
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "MajorVersion" ${KFW_MAJORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "MinorVersion" ${KFW_MINORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "PatchLevel" ${KFW_PATCHLEVEL}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "PatchLevel" ${KFW_PATCHLEVEL}
  
  ;Write start menu entries
  CreateDirectory "$SMPROGRAMS\${PROGRAM_NAME}"
  SetOutPath "$INSTDIR\bin"
  CreateShortCut  "$SMPROGRAMS\${PROGRAM_NAME}\Uninstall ${PROGRAM_NAME}.lnk" "$INSTDIR\Uninstall.exe"

  ReadINIStr $R0 $1 "Field 2" "State"  ; startup
  ReadINIStr $R1 $1 "Field 3" "State"  ; autoinit

  StrCmp $R1 "0" noauto
  CreateShortCut  "$SMPROGRAMS\${PROGRAM_NAME}\Leash Kerberos Ticket Manager.lnk" "$INSTDIR\bin\leash32.exe" "-autoinit" "$INSTDIR\bin\leash32.exe" 
  goto startshort
noauto:
  CreateShortCut  "$SMPROGRAMS\${PROGRAM_NAME}\Leash Kerberos Ticket Manager.lnk" "$INSTDIR\bin\leash32.exe" "" "$INSTDIR\bin\leash32.exe" 

startshort:
  StrCmp $R0 "0" nostart
  StrCmp $R1 "0" nostartauto
  CreateShortCut  "$SMSTARTUP\Leash Kerberos Ticket Manager.lnk" "$INSTDIR\bin\leash32.exe" "-autoinit" "$INSTDIR\bin\leash32.exe" 0 SW_SHOWMINIMIZED
  goto checkconflicts
nostartauto:  
  CreateShortCut  "$SMSTARTUP\Leash Kerberos Ticket Manager.lnk" "$INSTDIR\bin\leash32.exe" "" "$INSTDIR\bin\leash32.exe" 0 SW_SHOWMINIMIZED
  goto checkconflicts

nostart:
  Delete  "$SMSTARTUP\Leash Kerberos Ticket Manager.lnk"

checkconflicts:
  Call GetSystemPath
  Push "krb5_32.dll"
  Call SearchPath
  Pop  $R0
  StrCmp $R0 "" addpath

  Push $R0
  Call GetParent
  Pop $R0
  StrCmp $R0 "$INSTDIR\bin" addpath
  MessageBox MB_OK|MB_ICONINFORMATION|MB_TOPMOST "A previous installation of MIT Kerberos for Windows binaries has been found in folder $R0.  This may interfere with the use of the current installation."

addpath:
  ; Add kfw bin to path
  Push "$INSTDIR\bin"
  Call AddToSystemPath

  Call GetWindowsVersion
  Pop $R0
  StrCmp $R0 "2003" addAllowTgtKey
  StrCmp $R0 "2000" addAllowTgtKey
  StrCmp $R0 "XP"   addAllowTgtKey
  goto skipAllowTgtKey

addAllowTgtKey:
  ReadRegDWORD $R0 HKLM "SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" "AllowTGTSessionKey" 
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "AllowTGTSessionKeyBackup" $R0
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" "AllowTGTSessionKey" "1"
  ReadRegDWORD $R0 HKLM "SYSTEM\CurrentControlSet\Control\Lsa\Kerberos" "AllowTGTSessionKey" 
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "AllowTGTSessionKeyBackupXP" $R0
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control\Lsa\Kerberos" "AllowTGTSessionKey" "1"
skipAllowTgtKey:  

  ; The following are keys added for Terminal Server compatibility
  ; http://support.microsoft.com/default.aspx?scid=kb;EN-US;186499
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\leash32.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kinit.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\klist.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kdestroy.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\aklog.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\gss.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\gss-client.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\gss-server.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\k524init.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kpasswd.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kvno.exe" "Flags" 0x408
  WriteRegDWORD HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\ms2mit.exe" "Flags" 0x408

SectionEnd

;----------------------
; Kerberos for Windows SDK
Section "KfW SDK" secSDK

  RMDir /r "$INSTDIR\inc"
  RMDir /r "$INSTDIR\lib"
  RMDir /r "$INSTDIR\install"

  SetOutPath "$INSTDIR\inc\kclient"
  File /r "${KFW_INC_DIR}\kclient\*"  

  SetOutPath "$INSTDIR\inc\krb4"
  File /r "${KFW_INC_DIR}\krb4\*"  

  SetOutPath "$INSTDIR\inc\krb5"
  File /r "${KFW_INC_DIR}\krb5\*"  

  SetOutPath "$INSTDIR\inc\krbcc"
  File /r "${KFW_INC_DIR}\krbcc\*"  

  SetOutPath "$INSTDIR\inc\leash"
  File /r "${KFW_INC_DIR}\leash\*"  

  SetOutPath "$INSTDIR\inc\loadfuncs"
  File /r "${KFW_INC_DIR}\loadfuncs\*"  

  SetOutPath "$INSTDIR\inc\wshelper"
  File /r "${KFW_INC_DIR}\wshelper\*"  

  SetOutPath "$INSTDIR\lib\i386"
  File /r "${KFW_LIB_DIR}\*"

  SetOutPath "$INSTDIR\install"
  File /r "${KFW_INSTALL_DIR}\*"

  Call KFWCommon.Install
  
  ; KfW Reg entries
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "VersionString" ${KFW_VERSION}
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "Title" "KfW"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "Description" "${PROGRAM_NAME}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "PathName" "$INSTDIR"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "Software Type" "Authentication"
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "MajorVersion" ${KFW_MAJORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "MinorVersion" ${KFW_MINORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "PatchLevel" ${KFW_PATCHLEVEL}

  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "VersionString" ${KFW_VERSION}
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "Title" "KfW"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "Description" "${PROGRAM_NAME}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "PathName" "$INSTDIR"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "Software Type" "Authentication"
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "MajorVersion" ${KFW_MAJORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "MinorVersion" ${KFW_MINORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "PatchLevel" ${KFW_PATCHLEVEL}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\SDK\${KFW_VERSION}" "PatchLevel" ${KFW_PATCHLEVEL}
  
SectionEnd

;----------------------
; Kerberos for Windows Documentation
Section "KfW Documentation" secDocs

  RMDir /r "$INSTDIR\doc"

  SetOutPath "$INSTDIR\doc"
  File "${KFW_DOC_DIR}\relnotes.html"
  File "${KFW_DOC_DIR}\leash_userdoc.pdf"
   
  Call KFWCommon.Install
  
  ; KfW Reg entries
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "VersionString" ${KFW_VERSION}
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "Title" "KfW"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "Description" "${PROGRAM_NAME}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "PathName" "$INSTDIR"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "Software Type" "Authentication"
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "MajorVersion" ${KFW_MAJORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "MinorVersion" ${KFW_MINORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "PatchLevel" ${KFW_PATCHLEVEL}

  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "VersionString" ${KFW_VERSION}
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "Title" "KfW"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "Description" "${PROGRAM_NAME}"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "PathName" "$INSTDIR"
  WriteRegStr HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "Software Type" "Authentication"
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "MajorVersion" ${KFW_MAJORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "MinorVersion" ${KFW_MINORVERSION}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "PatchLevel" ${KFW_PATCHLEVEL}
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\Documentation\${KFW_VERSION}" "PatchLevel" ${KFW_PATCHLEVEL}
  
  ;Write start menu entries
  CreateDirectory "$SMPROGRAMS\${PROGRAM_NAME}"
  SetOutPath "$INSTDIR\doc"
  CreateShortCut  "$SMPROGRAMS\${PROGRAM_NAME}\Release Notes.lnk" "$INSTDIR\doc\relnotes.html" 
  CreateShortCut  "$SMPROGRAMS\${PROGRAM_NAME}\Leash User Documentation.lnk" "$INSTDIR\doc\leash_userdoc.pdf" 

SectionEnd

;Display the Finish header
;Insert this macro after the sections if you are not using a finish page
;!insertmacro MUI_SECTIONS_FINISHHEADER

;--------------------------------
;Installer Functions

Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
  
  ; Set the default install options
  Push $0

   Call IsUserAdmin
   Pop $R0
   StrCmp $R0 "true" checkVer

   MessageBox MB_OK|MB_ICONSTOP|MB_TOPMOST "You must be an administrator of this machine to install this software."
   Abort
   
checkVer:
  ; Check Version of Windows.   Do not install onto Windows 95
   Call GetWindowsVersion
   Pop $R0
   StrCmp $R0 "95" wrongVersion
   goto checkIPHLPAPI

wrongVersion:
   MessageBox MB_OK|MB_ICONSTOP|MB_TOPMOST "MIT ${PROGRAM_NAME} requires Microsoft Windows 98 or higher."
   Abort

checkIPHLPAPI:
   ClearErrors
   ReadEnvStr $R0 "WinDir"
   GetDLLVersion "$R0\System32\iphlpapi.dll" $R1 $R2
   IfErrors +1 +3 
   GetDLLVersion "$R0\System\iphlpapi.dll" $R1 $R2
   IfErrors iphlperror
   IntOp $R3 $R2 / 0x00010000
   IntCmpU $R3 1952 iphlpwarning checkprevious checkprevious

iphlperror:
   MessageBox MB_OK|MB_ICONSTOP|MB_TOPMOST "MIT ${PROGRAM_NAME} requires Internet Explorer version 5.01 or higher. IPHLPAPI.DLL is missing."
   Abort

iphlpwarning:
   MessageBox MB_OK|MB_ICONINFORMATION|MB_TOPMOST "IPHLPAPI.DLL must be upgraded.  Please install Internet Explorer 5.01 or higher."

checkprevious:
  ClearErrors
  ReadRegStr $R0 HKLM \
  "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
  "DisplayVersion"
  IfErrors contInstall
  StrCmp $R0 "${KFW_VERSION}" contInstall

  MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
  "${PROGRAM_NAME} is already installed. $\n$\nClick `OK` to remove the \
  previous version or `Cancel` to cancel this upgrade or downgrade." \
  IDOK uninst
  Abort
  
;Run the uninstaller
uninst:
  ReadRegStr $R0 HKLM \
  "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
  "UninstallString"
  ClearErrors
  ExecWait '$R0 _?=$INSTDIR' ;Do not copy the uninstaller to a temp file

  IfErrors no_remove_uninstaller
    ;You can either use Delete /REBOOTOK in the uninstaller or add some code
    ;here to remove the uninstaller. Use a registry key to check
    ;whether the user has chosen to uninstall. If you are using an uninstaller
    ;components page, make sure all sections are uninstalled.

  Push $R1
  Call RestartRequired
  Exch $R1
  StrCmp $R1 "1" RestartRequired RestartNotRequired 

RestartRequired:
   MessageBox MB_OK|MB_ICONSTOP|MB_TOPMOST "Please reboot and then restart the installer."
   Abort
 
RestartNotRequired:
no_remove_uninstaller:

contInstall:
   ; Our logic should be like this.
   ;     1) If no KfW components are installed, we do a clean install with default options. (Client/Docs)
   ;     2) If existing modules are installed, we keep them selected
   ;     3) If it is an upgrade, we set the text accordingly, else we mark it as a re-install
   ;  TODO: Downgrade?
   Call IsAnyKfWInstalled
   Pop $R0
   StrCmp $R0 "0" DefaultOptions
   
   Call ShouldClientInstall
   Pop $R2
   
   StrCmp $R2 "0" NoClient
   StrCmp $R2 "1" ReinstallClient
   StrCmp $R2 "2" UpgradeClient
   StrCmp $R2 "3" DowngradeClient
   
	SectionGetFlags ${secClient} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secClient} $0
    ;# !insertmacro SelectSection ${secClient}
   goto skipClient
NoClient:
	;StrCpy $1 ${secClient} ; Gotta remember which section we are at now...
	SectionGetFlags ${secClient} $0
	IntOp $0 $0 & ${SECTION_OFF}
	SectionSetFlags ${secClient} $0
   goto skipClient
UpgradeClient:
	SectionGetFlags ${secClient} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secClient} $0
   SectionSetText ${secClient} $(UPGRADE_CLIENT)
   goto skipClient
ReinstallClient:
	SectionGetFlags ${secClient} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secClient} $0
   SectionSetText ${secClient} $(REINSTALL_CLIENT)
   goto skipClient
DowngradeClient:
	SectionGetFlags ${secClient} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secClient} $0
   SectionSetText ${secClient} $(DOWNGRADE_CLIENT)
   goto skipClient

   
skipClient:   
   
   Call ShouldSDKInstall
   Pop $R2
   StrCmp $R2 "0" NoSDK
   StrCmp $R2 "1" ReinstallSDK
   StrCmp $R2 "2" UpgradeSDK
   StrCmp $R2 "3" DowngradeSDK
   
	SectionGetFlags ${secSDK} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secSDK} $0
	;# !insertmacro UnselectSection ${secSDK}
   goto skipSDK

UpgradeSDK:
   SectionGetFlags ${secSDK} $0
   IntOp $0 $0 | ${SF_SELECTED}
   SectionSetFlags ${secSDK} $0
   SectionSetText ${secSDK} $(UPGRADE_SDK)
   goto skipSDK

ReinstallSDK:
   SectionGetFlags ${secSDK} $0
   IntOp $0 $0 | ${SF_SELECTED}
   SectionSetFlags ${secSDK} $0
   SectionSetText ${secSDK} $(REINSTALL_SDK)
   goto skipSDK

DowngradeSDK:
   SectionGetFlags ${secSDK} $0
   IntOp $0 $0 | ${SF_SELECTED}
   SectionSetFlags ${secSDK} $0
   SectionSetText ${secSDK} $(DOWNGRADE_SDK)
   goto skipSDK
   
NoSDK:
	SectionGetFlags ${secSDK} $0
	IntOp $0 $0 & ${SECTION_OFF}
	SectionSetFlags ${secSDK} $0
	;# !insertmacro UnselectSection ${secSDK}
   goto skipSDK
   
skipSDK:

   Call ShouldDocumentationInstall
   Pop $R2
   StrCmp $R2 "0" NoDocumentation
   StrCmp $R2 "1" ReinstallDocumentation
   StrCmp $R2 "2" UpgradeDocumentation
   StrCmp $R2 "3" DowngradeDocumentation
   
	SectionGetFlags ${secDocs} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secDocs} $0
	;# !insertmacro UnselectSection ${secDocs}
   goto skipDocumentation

UpgradeDocumentation:
   SectionGetFlags ${secDocs} $0
   IntOp $0 $0 | ${SF_SELECTED}
   SectionSetFlags ${secDocs} $0
   SectionSetText ${secDocs} $(UPGRADE_DOCS)
   goto skipDocumentation

ReinstallDocumentation:
   SectionGetFlags ${secDocs} $0
   IntOp $0 $0 | ${SF_SELECTED}
   SectionSetFlags ${secDocs} $0
   SectionSetText ${secDocs} $(REINSTALL_DOCS)
   goto skipDocumentation

DowngradeDocumentation:
   SectionGetFlags ${secDocs} $0
   IntOp $0 $0 | ${SF_SELECTED}
   SectionSetFlags ${secDocs} $0
   SectionSetText ${secDocs} $(DOWNGRADE_DOCS)
   goto skipDocumentation
   
NoDocumentation:
	SectionGetFlags ${secDocs} $0
	IntOp $0 $0 & ${SECTION_OFF}
	SectionSetFlags ${secDocs} $0
	;# !insertmacro UnselectSection ${secDocs}
   goto skipDocumentation
   
skipDocumentation:
   goto end
   
DefaultOptions:
   ; Client Selected
	SectionGetFlags ${secClient} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secClient} $0

   ; SDK NOT selected
	SectionGetFlags ${secSDK} $0
	IntOp $0 $0 & ${SECTION_OFF}
	SectionSetFlags ${secSDK} $0
   
   ; Documentation selected
	SectionGetFlags ${secDocs} $0
	IntOp $0 $0 | ${SF_SELECTED}
	SectionSetFlags ${secDocs} $0
   goto end

end:
	Pop $0
  
   Push $R0
  
  ; See if we can set a default installation path...
  ReadRegStr $R0 HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion" "PathName"
  StrCmp $R0 "" TrySDK
  StrCpy $INSTDIR $R0
  goto Nope
  
TrySDK:
  ReadRegStr $R0 HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion" "PathName"
  StrCmp $R0 "" TryDocs
  StrCpy $INSTDIR $R0
  goto Nope

TryDocs:
  ReadRegStr $R0 HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion" "PathName"
  StrCmp $R0 "" TryRoot
  StrCpy $INSTDIR $R0
  goto Nope

TryRoot:
  ReadRegStr $R0 HKLM "${KFW_REGKEY_ROOT}" "InstallDir"
  StrCmp $R0 "" Nope
  StrCpy $INSTDIR $R0
  
Nope:
  Pop $R0
  
  GetTempFilename $0
  File /oname=$0 KfWConfigPage.ini
  GetTempFilename $1
  File /oname=$1 KfWConfigPage2.ini
  
FunctionEnd


;--------------------------------
; These are our cleanup functions
Function .onInstFailed
Delete $0
Delete $1
FunctionEnd

Function .onInstSuccess
Delete $0
Delete $1
FunctionEnd


;--------------------------------
;Descriptions

  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${secClient} $(DESC_secClient)
  !insertmacro MUI_DESCRIPTION_TEXT ${secSDK} $(DESC_secSDK)
  !insertmacro MUI_DESCRIPTION_TEXT ${secDocs} $(DESC_secDocs)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END
 
;--------------------------------
;Uninstaller Section

Section "Uninstall"
  ; Make sure the user REALLY wants to do this, unless they did a silent uninstall, in which case...let them!
  IfSilent StartRemove     ; New in v2.0b4
  MessageBox MB_YESNO "Are you sure you want to remove MIT ${PROGRAM_NAME} from this machine?" IDYES StartRemove
  abort
  
StartRemove:
  
  SetShellVarContext all
  ; Stop the running processes
  GetTempFileName $R0
  File /oname=$R0 "Killer.exe"
  nsExec::Exec '$R0 leash32.exe'
  nsExec::Exec '$R0 krbcc32s.exe'

  Push "$INSTDIR\bin"
  Call un.RemoveFromSystemPath
  
  ; Delete documentation
  Delete "$INSTDIR\doc\relnotes.html"
  Delete "$INSTDIR\doc\leash_userdoc.pdf"

   Delete /REBOOTOK "$INSTDIR\bin\aklog.exe"
   Delete /REBOOTOK "$INSTDIR\bin\comerr32.dll"
   Delete /REBOOTOK "$INSTDIR\bin\gss.exe"
   Delete /REBOOTOK "$INSTDIR\bin\gss-client.exe"
   Delete /REBOOTOK "$INSTDIR\bin\gss-server.exe"
   Delete /REBOOTOK "$INSTDIR\bin\gssapi32.dll"
   Delete /REBOOTOK "$INSTDIR\bin\k524init.exe"
   Delete /REBOOTOK "$INSTDIR\bin\kclnt32.dll"
   Delete /REBOOTOK "$INSTDIR\bin\kdestroy.exe"
   Delete /REBOOTOK "$INSTDIR\bin\kinit.exe"
   Delete /REBOOTOK "$INSTDIR\bin\klist.exe"   
   Delete /REBOOTOK "$INSTDIR\bin\kpasswd.exe"   
   Delete /REBOOTOK "$INSTDIR\bin\kvno.exe"   
   Delete /REBOOTOK "$INSTDIR\bin\krb5_32.dll" 
   Delete /REBOOTOK "$INSTDIR\bin\krb524.dll"  
   Delete /REBOOTOK "$INSTDIR\bin\krbcc32.dll" 
   Delete /REBOOTOK "$INSTDIR\bin\krbcc32s.exe"
   Delete /REBOOTOK "$INSTDIR\bin\krbv4w32.dll"
!ifdef OLDHELP
   Delete /REBOOTOK "$INSTDIR\bin\leash32.hlp"
!else
   Delete /REBOOTOK "$INSTDIR\bin\leash32.chm" 
!endif
   Delete /REBOOTOK "$INSTDIR\bin\leashw32.dll"
   Delete /REBOOTOK "$INSTDIR\bin\ms2mit.exe"  
   Delete /REBOOTOK "$INSTDIR\bin\wshelp32.dll"
   Delete /REBOOTOK "$INSTDIR\bin\xpprof32.dll"

!IFDEF DEBUG
   Delete /REBOOTOK "$INSTDIR\bin\aklog.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\comerr32.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\gss.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\gss-client.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\gss-server.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\gssapi32.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\k524init.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\kclnt32.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\kdestroy.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\kinit.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\klist.pdb"   
   Delete /REBOOTOK "$INSTDIR\bin\kpasswd.pdb"   
   Delete /REBOOTOK "$INSTDIR\bin\kvno.pdb"   
   Delete /REBOOTOK "$INSTDIR\bin\krb5_32.pdb" 
   Delete /REBOOTOK "$INSTDIR\bin\krb524.pdb"  
   Delete /REBOOTOK "$INSTDIR\bin\krbcc32.pdb" 
   Delete /REBOOTOK "$INSTDIR\bin\krbcc32s.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\krbv4w32.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\leashw32.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\ms2mit.pdb"  
   Delete /REBOOTOK "$INSTDIR\bin\wshelp32.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\xpprof32.pdb"

!IFDEF CL_1310
   Delete /REBOOTOK "$INSTDIR\bin\msvcr71d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcr71d.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp71d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp71d.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\mfc71d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\mfc71d.pdb"
!ELSE
!IFDEF CL_1300
   Delete /REBOOTOK "$INSTDIR\bin\msvcr70d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcr70d.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp70d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp70d.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\mfc70d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\mfc70d.pdb"
!ELSE
   Delete /REBOOTOK "$INSTDIR\bin\mfc42d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\mfc42d.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp60d.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp60d.pdb"
   Delete /REBOOTOK "$INSTDIR\bin\msvcrtd.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcrtd.pdb"
!ENDIF
!ENDIF
!ELSE
!IFDEF CL_1310
   Delete /REBOOTOK "$INSTDIR\bin\mfc71.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcr71.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp71.dll"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71CHS.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71CHT.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71DEU.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71ENU.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71ESP.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71FRA.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71ITA.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71JPN.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC71KOR.DLL"
!ELSE
!IFDEF CL_1300
   Delete /REBOOTOK "$INSTDIR\bin\mfc70.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcr70.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp70.dll"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70CHS.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70CHT.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70DEU.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70ENU.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70ESP.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70FRA.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70ITA.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70JPN.DLL"
   Delete /REBOOTOK "$INSTDIR\bin\MFC70KOR.DLL"
!ELSE
   Delete /REBOOTOK "$INSTDIR\bin\mfc42.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcp60.dll"
   Delete /REBOOTOK "$INSTDIR\bin\msvcrt.dll"
!ENDIF
!ENDIF
!ENDIF
   Delete /REBOOTOK "$INSTDIR\bin\psapi.dll"

  RMDir  "$INSTDIR\bin"
  RmDir  "$INSTDIR\doc"
  RmDir  "$INSTDIR\lib"
  RmDir  "$INSTDIR\inc"
  RmDir  "$INSTDIR\install"
  RMDir  "$INSTDIR"
  
  Delete  "$SMPROGRAMS\${PROGRAM_NAME}\Uninstall ${PROGRAM_NAME}.lnk"
  Delete  "$SMPROGRAMS\${PROGRAM_NAME}\Leash Kerberos Ticket Manager.lnk"
  Delete  "$SMPROGRAMS\${PROGRAM_NAME}\Release Notes.lnk"
  Delete  "$SMPROGRAMS\${PROGRAM_NAME}\Leash User Documentation.lnk"
  RmDir   "$SMPROGRAMS\${PROGRAM_NAME}"
  Delete  "$SMSTARTUP\Leash Kerberos Ticket Manager.lnk"

   IfSilent SkipAsk
;  IfFileExists "$WINDIR\krb5.ini" CellExists SkipDelAsk
;  RealmExists:
  MessageBox MB_YESNO "Would you like to keep your configuration files?" IDYES SkipDel
  SkipAsk:
  Delete "$WINDIR\krb5.ini"
  Delete "$WINDIR\krb.con"
  Delete "$WINDIR\krbrealm.con"
  
  SkipDel:
  Delete "$INSTDIR\Uninstall.exe"

  ; Restore previous value of AllowTGTSessionKey 
  ReadRegDWORD $R0 HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "AllowTGTSessionKeyBackup"
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" "AllowTGTSessionKey" $R0
  ReadRegDWORD $R0 HKLM "${KFW_REGKEY_ROOT}\Client\${KFW_VERSION}" "AllowTGTSessionKeyBackupXP"
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control\Lsa\Kerberos" "AllowTGTSessionKey" $R0

  ; The following are keys added for Terminal Server compatibility
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\leash32.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kinit.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\klist.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kdestroy.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\aklog.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\gss.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\gss-client.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\gss-server.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\k524init.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kpasswd.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\kvno.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility\Applications\ms2mit.exe"

  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Client\CurrentVersion"
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Client"
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Documentation\CurrentVersion"
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\Documentation"
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\SDK\CurrentVersion"
  DeleteRegKey HKLM "${KFW_REGKEY_ROOT}\SDK"
  DeleteRegKey /ifempty HKLM "${KFW_REGKEY_ROOT}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}"
 
  RMDir  "$INSTDIR"

SectionEnd

;--------------------------------
;Uninstaller Functions

Function un.onInit

  ;Get language from registry
  ReadRegStr $LANGUAGE ${MUI_LANGDLL_REGISTRY_ROOT} "${MUI_LANGDLL_REGISTRY_KEY}" "${MUI_LANGDLL_REGISTRY_VALUENAME}"
                                                    
FunctionEnd

Function un.onUninstSuccess

   MessageBox MB_OK "Please reboot your machine to complete uninstallation of the software"

FunctionEnd

;------------------------------
; Get the Configurations files from the Internet

Function kfw.GetConfigFiles

;Check if we should download Config Files
ReadINIStr $R0 $0 "Field 4" "State"
StrCmp $R0 "1" DoDownload

;Do nothing if we're keeping the existing file
ReadINIStr $R0 $0 "Field 2" "State"
StrCmp $R0 "1" done

ReadINIStr $R0 $0 "Field 3" "State"
StrCmp $R0 "1" UsePackaged

; If none of these, grab file from other location
goto CheckOther

DoDownload:
   ReadINIStr $R0 $0 "Field 5" "State"
   NSISdl::download "$R0/krb5.ini" "$WINDIR\krb5.ini"
   NSISdl::download "$R0/krb.con" "$WINDIR\krb.con"
   NSISdl::download "$R0/krbrealm.con" "$WINDIR\krbrealm.con"
   Pop $R0 ;Get the return value
   StrCmp $R0 "success" done
   MessageBox MB_OK|MB_ICONSTOP "Download failed: $R0"
   goto done

UsePackaged:
   SetOutPath "$WINDIR"
   File "${KFW_CONFIG_DIR}\krb5.ini"
   File "${KFW_CONFIG_DIR}\krb.con"
   File "${KFW_CONFIG_DIR}\krbrealm.con"
   goto done
   
CheckOther:
   ReadINIStr $R0 $0 "Field 7" "State"
   StrCmp $R0 "" done
   CopyFiles "$R0\krb5.ini" "$WINDIR\krb5.ini"
   CopyFiles "$R0\krb.con" "$WINDIR\krb.con"
   CopyFiles "$R0\krbrealm.con" "$WINDIR\krbrealm.con"
   
done:

FunctionEnd



;-------------------------------
;Do the page to get the Config files

Function KFWPageGetConfigFiles
  ; Skip this page if we are not installing the client
  SectionGetFlags ${secClient} $R0
  IntOp $R0 $R0 & ${SF_SELECTED}
  StrCmp $R0 "0" Skip
  
  ; Set the install options here
  
startOver:
  WriteINIStr $0 "Field 2" "Flags" "DISABLED"
  WriteINIStr $0 "Field 3" "State" "1"
  WriteINIStr $0 "Field 4" "State" "0"
  WriteINIStr $0 "Field 6" "State" "0"
  WriteINIStr $0 "Field 3" "Text"  "Use packaged configuration files for the ${SAMPLE_CONFIG_REALM} realm."
  WriteINIStr $0 "Field 5" "State"  "${HTTP_CONFIG_URL}"  

  ; If there is an existing krb5.ini file, allow the user to choose it and make it default
  IfFileExists "$WINDIR\krb5.ini" +1 notpresent
  WriteINIStr $0 "Field 2" "Flags" "ENABLED"
  WriteINIStr $0 "Field 2" "State" "1"
  WriteINIStr $0 "Field 3" "State" "0"
  
  notpresent:
  
  !insertmacro MUI_HEADER_TEXT "Kerberos Configuration" "Please choose a method for installing the Kerberos Configuration files:" 
  InstallOptions::dialog $0
  Pop $R1
  StrCmp $R1 "cancel" exit
  StrCmp $R1 "back" done
  StrCmp $R1 "success" done
exit: Quit
done:

   ; Check that if a file is set, a valid filename is entered...
   ReadINIStr $R0 $0 "Field 6" "State"
   StrCmp $R0 "1" CheckFileName
   
   ;Check if a URL is specified, one *IS* specified
   ReadINIStr $R0 $0 "Field 4" "State"
   StrCmp $R0 "1" CheckURL Skip
   
   CheckURL:
   ReadINIStr $R0 $0 "Field 5" "State"
   StrCmp $R0 "" +1 Skip
   MessageBox MB_OK|MB_ICONSTOP $(URLError)
   WriteINIStr $0 "Field 4" "State" "0"
   goto startOver
   
   CheckFileName:
   ReadINIStr $R0 $0 "Field 7" "State"
   IfFileExists "$R0\krb5.ini" Skip

   MessageBox MB_OK|MB_ICONSTOP $(ConfigFileError)
   WriteINIStr $0 "Field 6" "State" "0"
   goto startOver
   
   Skip:
   
FunctionEnd


;-------------------------------
;Do the page to get the Startup Configuration

Function KFWPageGetStartupConfig
  ; Skip this page if we are not installing the client
  SectionGetFlags ${secClient} $R0
  IntOp $R0 $R0 & ${SF_SELECTED}
  StrCmp $R0 "0" Skip
  
  ; Set the install options here
  
  !insertmacro MUI_HEADER_TEXT "Leash Ticket Manager Setup" "Please select Leash ticket manager setup options:" 
  InstallOptions::dialog $1
  Pop $R1
  StrCmp $R1 "cancel" exit
  StrCmp $R1 "back" done
  StrCmp $R1 "success" done
exit: 
  Quit
done:
skip:
   
FunctionEnd


;-------------
; Common install routines for each module
Function KFWCommon.Install

  WriteRegStr HKLM "${KFW_REGKEY_ROOT}" "InstallDir" $INSTDIR

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayName" "${PROGRAM_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "UninstallString" "$INSTDIR\uninstall.exe"
!ifndef DEBUG
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayVersion" "${KFW_VERSION}"
!else
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayVersion" "${KFW_VERSION} Checked/Debug"
!endif
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "URLInfoAbout" "http://web.mit.edu/kerberos/"

!ifdef DEBUG
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\CurrentVersion" "Debug" 1
  WriteRegDWORD HKLM "${KFW_REGKEY_ROOT}\${KFW_VERSION}" "Debug" 1
!else
   ; Delete the DEBUG string
   DeleteRegValue HKLM "${KFW_REGKEY_ROOT}\CurrentVersion" "Debug"
   DeleteRegValue HKLM "${KFW_REGKEY_ROOT}\${KFW_VERSION}" "Debug"
!endif

  WriteUninstaller "$INSTDIR\Uninstall.exe"
FunctionEnd


;-------------------------------
; Check if the client should be checked for default install
Function ShouldClientInstall
   Push $R0
   StrCpy $R2 "Client"
   Call GetInstalledVersion
   Pop $R0
   
   StrCmp $R0 "" NotInstalled
   ; Now we see if it's an older or newer version

   Call GetInstalledVersionMajor
   Pop $R0
   IntCmpU $R0 ${KFW_MAJORVERSION} +1 Upgrade Downgrade

   Call GetInstalledVersionMinor
   Pop $R0
   IntCmpU $R0 ${KFW_MINORVERSION} +1 Upgrade Downgrade
   
   Call GetInstalledVersionPatch
   Pop $R0
   IntCmpU $R0 ${KFW_PATCHLEVEL} Reinstall Upgrade Downgrade
   
Reinstall:
   StrCpy $R0 "1"
   Exch $R0
   goto end
   
Upgrade:
   StrCpy $R0 "2"
   Exch $R0
   goto end
   
Downgrade:
   StrCpy $R0 "3"
   Exch $R0
   goto end
   
NotInstalled:
   StrCpy $R0 "0"
   Exch $R0
end:   
FunctionEnd

;-------------------------------
; Check how the Documentation options should be set
Function ShouldDocumentationInstall
   Push $R0
   StrCpy $R2 "Documentation"
   Call GetInstalledVersion
   Pop $R0
   
   StrCmp $R0 "" NotInstalled
   ; Now we see if it's an older or newer version

   Call GetInstalledVersionMajor
   Pop $R0
   IntCmpU $R0 ${KFW_MAJORVERSION} +1 Upgrade Downgrade

   Call GetInstalledVersionMinor
   Pop $R0
   IntCmpU $R0 ${KFW_MINORVERSION} +1 Upgrade Downgrade
   
   Call GetInstalledVersionPatch
   Pop $R0
   IntCmpU $R0 ${KFW_PATCHLEVEL} Reinstall Upgrade Downgrade
   
Reinstall:
   StrCpy $R0 "1"
   Exch $R0
   goto end
   
Upgrade:
   StrCpy $R0 "2"
   Exch $R0
   goto end
   
Downgrade:
   StrCpy $R0 "3"
   Exch $R0
   goto end
   
   
NotInstalled:
   StrCpy $R0 "0"
   Exch $R0
end:   
FunctionEnd


;-------------------------------
; Check how the SDK options should be set
Function ShouldSDKInstall
   Push $R0
   StrCpy $R2 "SDK"
   Call GetInstalledVersion
   Pop $R0
   
   StrCmp $R0 "" NotInstalled
   ; Now we see if it's an older or newer version

   Call GetInstalledVersionMajor
   Pop $R0
   IntCmpU $R0 ${KFW_MAJORVERSION} +1 Upgrade Downgrade

   Call GetInstalledVersionMinor
   Pop $R0
   IntCmpU $R0 ${KFW_MINORVERSION} +1 Upgrade Downgrade
   
   Call GetInstalledVersionPatch
   Pop $R0
   IntCmpU $R0 ${KFW_PATCHLEVEL} Reinstall Upgrade Downgrade
   
Reinstall:
   StrCpy $R0 "1"
   Exch $R0
   goto end
   
Upgrade:
   StrCpy $R0 "2"
   Exch $R0
   goto end
   
Downgrade:
   StrCpy $R0 "3"
   Exch $R0
   goto end
   
   
NotInstalled:
   StrCpy $R0 "0"
   Exch $R0
end:   
FunctionEnd

; See if KfW SDK is installed
; Returns: "1" if it is, 0 if it is not (on the stack)
Function IsSDKInstalled
   Push $R0
   StrCpy $R2 "SDK"
   Call GetInstalledVersion
   Pop $R0
   
   StrCmp $R0 "" NotInstalled
   
   StrCpy $R0 "1"
   Exch $R0
   goto end
   
NotInstalled:
   StrCpy $R0 "0"
   Exch $R0
end:   
FunctionEnd


; See if KfW Client is installed
; Returns: "1" if it is, 0 if it is not (on the stack)
Function IsClientInstalled
   Push $R0
   StrCpy $R2 "Client"
   Call GetInstalledVersion
   Pop $R0
   
   StrCmp $R0 "" NotInstalled
   
   StrCpy $R0 "1"
   Exch $R0
   goto end
   
NotInstalled:
   StrCpy $R0 "0"
   Exch $R0
end:   
FunctionEnd



; See if KfW Documentation is installed
; Returns: "1" if it is, 0 if it is not (on the stack)
Function IsDocumentationInstalled
   Push $R0
   StrCpy $R2 "Documentation"
   Call GetInstalledVersion
   Pop $R0
   
   StrCmp $R0 "" NotInstalled
   
   StrCpy $R0 "1"
   Exch $R0
   goto end
   
NotInstalled:
   StrCpy $R0 "0"
   Exch $R0
end:   
FunctionEnd



;Check to see if any KfW component is installed
;Returns: Value on stack: "1" if it is, "0" if it is not
Function IsAnyKfWInstalled
   Push $R0
   Push $R1
   Push $R2
   Call IsClientInstalled
   Pop $R0
   Call IsSDKInstalled
   Pop $R1
   Call IsDocumentationInstalled
   Pop $R2
   ; Now we must see if ANY of the $Rn values are 1
   StrCmp $R0 "1" SomethingInstalled
   StrCmp $R1 "1" SomethingInstalled
   StrCmp $R2 "1" SomethingInstalled
   ;Nothing installed
   StrCpy $R0 "0"
   goto end
SomethingInstalled:
   StrCpy $R0 "1"
end:
   Pop $R2
   Pop $R1
   Exch $R0
FunctionEnd

;--------------------------------
;Handle what must and what must not be installed
Function .onSelChange
   ; If they install the SDK, they MUST install the client
   SectionGetFlags ${secSDK} $R0
   IntOp $R0 $R0 & ${SF_SELECTED}
   StrCmp $R0 "1" MakeClientSelected
   goto end
   
MakeClientSelected:
   SectionGetFlags ${secClient} $R0
   IntOp $R0 $R0 | ${SF_SELECTED}
   SectionSetFlags ${secClient} $R0
   
end:
FunctionEnd

