===============================================================================
  TildaUnlocker  v1.0
  Technical documentation (Readme)
===============================================================================

  Developer : ExEintel
  Utility   : Anti-malware & system hygiene tool
  Platform  : Windows 10 / 11  (also Windows Recovery Environment / WinPE)
  Language  : English (interface and this document)
  Written in: C (Win32 API)
  Compiled  : MinGW-w64 gcc


------------------------------------------------------------------------------
1. WHAT IS TILDAUNLOCKER
------------------------------------------------------------------------------
TildaUnlocker is a console utility for detecting, disabling and removing
malicious software (viruses, trojans, rootkits, hijackers, unwanted startup
entries) and for keeping the system clean. It provides a compact set of
system tools inside a single executable:

  * Mini Explorer        - navigate, find, copy, move, delete, wipe files
  * Mini task manager    - list, inspect, terminate, suspend processes
  * Services & drivers   - inspect and manage Windows services and drivers
  * Registry operator    - read, write, search and delete registry data
  * Autostart editor     - review and clean every autostart location
  * Integrity check      - verify critical system files are intact
  * Threat scan          - quick scan for common malware traces
  * Network diagnostics  - connections, proxy and DNS configuration
  * Security status      - UAC, Defender, Firewall, Windows Update
  * Recovery support     - designed to run inside the WinPE environment

The program is fully read-only by default; destructive commands (del, copy,
regwrite, regdel, kill, sstart/sstop/sdelete, ...) require the user to call
them explicitly. Run with Administrator rights for full functionality.


------------------------------------------------------------------------------
2. PROJECT STRUCTURE
------------------------------------------------------------------------------
TildaUnlocker
    |-- tildaunlocker.exe   - the executable program
    |-- Readme.txt          - this technical documentation
    |-- sourse\
         |-- main.c         - C source code of the program
         |-- logo.rc        - Windows resource script (icon + version info)
         |-- logo.png       - original logo (1000x1000, PNG)
         |-- logo.ico       - multi-size icon (256..16 px) generated from
         |                    logo.png with FFmpeg and embedded into the exe
         `-- logo.o         - compiled resource object (build artifact)


------------------------------------------------------------------------------
3. CALL SCHEMA
------------------------------------------------------------------------------
  tildaunlocker.exe  <command>  [parameters]

  * Command names are case-insensitive.
  * Parameters are separated by spaces; quote paths that contain spaces:
        tildaunlocker.exe ls "C:\Program Files"
  * Running the program without arguments prints the full help.
  * "help" prints the same command reference at any time.


------------------------------------------------------------------------------
4. COMMAND REFERENCE
------------------------------------------------------------------------------

--- 4.1  Mini Explorer (file system) ----------------------------------------

  ls <path>                  List a directory: attributes, size, date, name.
       Default (no path)     Lists the current directory.
  tree <path>                Print a recursive directory tree (max 8 levels).
  find <root> [mask]         Recursively search for files.
                             mask supports '*' and '?' (case-insensitive).
                             Example: find C:\Users\ExEintel *.dll
  del <path>                 Delete a file or a whole folder tree.
                             Hidden/read-only/system attributes are cleared
                             automatically before deletion.
  copy <src> <dst>           Copy a file or a folder tree.
  move <src> <dst>           Move/rename a file or folder (overwrites).
  mkdir <path>               Create a directory.
  rmdir <path>               Remove an EMPTY directory.
  attr <h|s|r|a> <path>      Toggle attribute of a file or folder:
                             h = hidden, s = system, r = read-only, a = archive
  wiper <path>               Secure erase: overwrite the file with zeros,
                             truncate it, then delete it.

  Relative paths are resolved against the current directory.

--- 4.2  Mini task manager (processes) --------------------------------------

  ps                         List processes: PID, parent PID, priority class,
                             working-set memory, executable name.
  task <pid|name>            Detailed info about one process: image path,
                             priority, memory, threads, session, parent.
  kill <pid|name>            Terminate a process (by PID or image name).
  priority <pid> <level>     Set process priority:
                             idle | low | normal | high | rt
  suspend <pid|name>         Suspend every thread of a process (good for
                             freezing an active infection).
  resume <pid|name>          Resume every thread of a process.
  parent <pid|name>          Show the parent process ID.

--- 4.3  Services & drivers --------------------------------------------------

  services                   List all Windows services: name, start type
                             (BOOT/SYSTEM/AUTO/MANUAL/DISABLED), state, PID,
                             display name.
  sconfig <name>             Show configuration of one service: binary path,
                             account, start type, error control.
  sstart <name>              Start a service (Administrator required).
  sstop <name>               Stop a service (Administrator required).
  sdelete <name>             Delete a service - often needed to remove
                             malicious services (Administrator required).
  drivers                    List all kernel / file-system drivers.
  drvinfo <name>             Show details of one driver.

--- 4.4  Registry operator ---------------------------------------------------

  Key paths must start with a hive:
     HKLM\   HKEY_LOCAL_MACHINE
     HKCU\   HKEY_CURRENT_USER
     HKCR\   HKEY_CLASSES_ROOT
     HKU\    HKEY_USERS
     HKCC\   HKEY_CURRENT_CONFIG
  (the HKEY_... full forms are also accepted)

  reglist <key>              List subkeys of a key.
  regvalues <key>            List all values of a key with type and data.
  regread <key> [value]      Read one value (default value if omitted).
  regwrite <key> <name>      Write a value:
           <REG_SZ|REG_DWORD|REG_QWORD> <data>
                             Types: REG_SZ, REG_EXPAND_SZ, REG_DWORD,
                             REG_QWORD. Numbers accept decimal or 0x hex.
                             The key is created if it does not exist.
  regdel <key>               Delete a key and everything below it.
  regdelval <key> <name>     Delete a single value.
  regsearch <key> <text>     Search a whole subtree: any value name or
                             REG_SZ value data containing <text> is printed.
  regdump <key>              Print the key tree as text (regedit-like).

  Examples:
    tildaunlocker.exe regvalues HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    tildaunlocker.exe regwrite HKLM\SOFTWARE\Demo\Test myval REG_DWORD 0x1
    tildaunlocker.exe regsearch HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run "svchost"
    tildaunlocker.exe regdelval HKCU\Software\Microsoft\Windows\CurrentVersion\Run badentry

--- 4.5  Autostart editor ----------------------------------------------------

  autoruns                   Full autostart report. Checks:
                             - HKCU/HKLM  Run and RunOnce keys
                             - HKLM/HKCU  Policies\Explorer\Run
                             - Winlogon   (Userinit / Shell)
                             - user and common Startup folders
                             - auto-start services and drivers
                             Entries pointing into temporary folders are
                             flagged with "[!]".
  areg                       Registry Run / RunOnce / Winlogon keys only.
  astartup                   Startup folders only.
  aservice                   Auto-start services only.
  adriver                    Boot/System drivers only.
  atask                      Scheduled tasks (via schtasks).

  Typical malware cleanup workflow:
    1) tildaunlocker.exe autoruns          -> review every autostart
    2) tildaunlocker.exe kill <name>       -> stop running malware
    3) tildaunlocker.exe regdelval <key> <name>  -> remove bad entry
    4) tildaunlocker.exe del <path>        -> delete malware file
    5) tildaunlocker.exe sdelete <name>    -> remove malicious service

--- 4.6  System integrity & protection --------------------------------------

  integrity                  System integrity check:
                             - presence of critical system files
                               (kernel32.dll, ntdll.dll, user32.dll,
                                services.exe, lsass.exe, winload.exe, ...)
                             - Winlogon Userinit / Shell values
                             - sfc /verifyonly if available
                             (sfc needs an elevated, normal session; it is
                             not available inside WinPE)
  scan                       Quick threat scan:
                             1) hosts file redirection analysis
                             2) running processes launched from TEMP folders
                             3) unusual HKCU/HKLM Run entries
  secpolicy                  Security policy diagnostic: UAC (LUA), LSA
                             settings, legal notice.
  bootconfig                 View the boot configuration (bcdedit /enum).
  hosts                      Display the hosts file content.
  lsa                        Show LSA protection (RunAsPPL) status.
  safeboot                   Show which services/drivers are loaded in
                             Safe Mode (Minimal and Network branches).

--- 4.7  Network -------------------------------------------------------------

  netstat                    List active TCP and UDP connections with the
                             owning process ID. Use 'task <pid>' to identify
                             the process. Useful for spotting beaconing /
                             C2 connections of malware.
  proxy                      Show the user's proxy settings (ProxyEnable,
                             ProxyServer, AutoConfigURL).
  dns                        Show DNS servers configured per network
                             interface (NameServer / DHCP).

--- 4.8  Security status -----------------------------------------------------

  uac                        UAC (User Account Control) status.
  defender                   Windows Defender service state and policy.
  firewall                   Windows Firewall service state and per-profile
                             EnableFirewall flags.
  updates                    Windows Update service state and AU options.

  NOTE: inside WinPE these services are normally absent; the commands then
  print "not present" instead of failing.

--- 4.9  Recovery environment & information ---------------------------------

  winpe                      Detect the current environment and print facts:
                             system dir, windows dir, RAM disk, admin rights.
  mountcheck                 List every mounted volume: drive letter, type,
                             file system, volume label, free/total space.
  info                       System information: OS build, product, computer
                             name, architecture, CPU count, memory, rights.
  version                    Program name and version.
  help                       Print this command reference.


------------------------------------------------------------------------------
5. WORKING IN THE RECOVERY ENVIRONMENT (WINPE)
------------------------------------------------------------------------------
TildaUnlocker is compiled against the standard Win32 API and does not depend
on the full desktop environment, so it runs from a WinPE / Windows RE shell
(e.g. from a recovery command prompt) as well as from normal Windows.

  * Copy tildaunlocker.exe onto a USB stick and run it from the recovery
    command prompt (Shift+F10 in Windows setup or "Command Prompt" in
    Windows RE).
  * In WinPE the X:\ drive is a RAM disk; the real system is usually on C:\.
  * sfc /verifyonly, Defender, Firewall and Update checks are not available
    in WinPE and are skipped gracefully.
  * Registry and file commands work on the offline/online registry of the
    running WinPE instance; to edit the registry of the installed (offline)
    system you may need to load its hive with reg load first. When WinPE is
    booted from the installed system's partition the Run keys and Startup
    folders of that system can be read directly.

  Typical WinPE use case (infected machine that will not boot):
    1) Boot the machine from Windows installation / recovery media.
    2) Open Command Prompt, go to the USB drive.
    3) tildaunlocker.exe mountcheck        -> find the system partition
    4) tildaunlocker.exe autoruns          -> inspect autostart entries
    5) tildaunlocker.exe regdelval ...     -> remove malicious entries
    6) tildaunlocker.exe del <path>        -> delete malware files
    7) tildaunlocker.exe sdelete <name>    -> remove malicious services
    8) Reboot normally.


------------------------------------------------------------------------------
6. BUILD INSTRUCTIONS (from source)
------------------------------------------------------------------------------
Prerequisites:
  * MinGW-w64 gcc (tested with MinGW-W64 i686 gcc 16.1.0)
  * FFmpeg (only needed once, to regenerate logo.ico from logo.png)
  * Windows SDK headers (shipped with MinGW-w64)

Build steps:

  1) Create the icon (already done, redo only if you change logo.png):
       ffmpeg -i logo.png -vf scale=256:256  ico_s256.png
       ffmpeg -i logo.png -vf scale=128:128  ico_s128.png
       ffmpeg -i logo.png -vf scale=64:64    ico_s64.png
       ffmpeg -i logo.png -vf scale=48:48    ico_s48.png
       ffmpeg -i logo.png -vf scale=32:32    ico_s32.png
       ffmpeg -i logo.png -vf scale=16:16    ico_s16.png
       ffmpeg -y -i ico_s256.png -i ico_s128.png -i ico_s64.png -i ico_s48.png \
              -i ico_s32.png -i ico_s16.png -map 0 -map 1 -map 2 -map 3 -map 4 -map 5 \
              -c copy logo.ico

  2) Compile the resource script (embeds the icon and version info):
       windres logo.rc -o logo.o

  3) Compile and link the program:
       gcc -O2 -o tildaunlocker.exe main.c logo.o \
           -ladvapi32 -lshell32 -lpsapi -liphlpapi -lws2_32 -luser32

  4) (Optional) strip the binary:
       strip --strip-all tildaunlocker.exe

The resulting tildaunlocker.exe is self-contained; no DLLs beyond the
standard system libraries are required.


------------------------------------------------------------------------------
7. RETURN CODES
------------------------------------------------------------------------------
  0  - success / information printed
  1  - unknown command or generic error


------------------------------------------------------------------------------
8. NOTES & SAFETY
------------------------------------------------------------------------------
  * This tool is designed for system administrators and technically
    experienced users. Misuse of destructive commands (del, regdel, sdelete,
    kill) can damage the operating system.
  * Read-only commands (ls, tree, find, ps, task, services, drivers, registry
    reads, regsearch, regdump, integrity, scan, netstat, info, ...) never
    modify the system.
  * No data is sent anywhere: the tool is fully offline.
  * Always back up the registry (reg export) before editing it.
  * The program requires Administrator rights to stop/delete services, to
    terminate protected processes and to write to HKLM or system files.

  (c) 2026 ExEintel. Provided as-is, without warranty of any kind.
===============================================================================
