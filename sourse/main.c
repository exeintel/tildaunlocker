/*
 * ============================================================================
 *  TildaUnlocker  v1.0
 *  ---------------------------------------------------------------------------
 *  Anti-malware & system hygiene utility for Windows 10 / 11.
 *
 *  Developer : ExEintel
 *  Language  : C (Win32 API)
 *  Compiler  : MinGW-w64 gcc
 *
 *  Build:
 *    windres logo.rc -o logo.o
 *    gcc -O2 -o tildaunlocker.exe main.c logo.o \
 *        -ladvapi32 -lshell32 -lpsapi -liphlpapi -lws2_32 -luser32
 *
 *  TildaUnlocker also runs inside the Windows Recovery Environment (WinPE),
 *  so an infected machine can be inspected and cleaned even if a normal
 *  boot fails.  English only interface.
 *
 *  Call schema:  tildaunlocker.exe  <command>  [parameters]
 * ============================================================================
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef snprintf
#define snprintf _snprintf
#endif

static const char *APP_VER = "1.0";

/* ============================================================================
 * 1.  General helpers
 * ==========================================================================*/

static int is_admin(void)
{
    HANDLE h = NULL;
    TOKEN_ELEVATION el;
    DWORD sz = 0;
    int ok = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h))
        return 0;
    ZeroMemory(&el, sizeof(el));
    ok = GetTokenInformation(h, TokenElevation, &el, sizeof(el), &sz) && el.TokenIsElevated;
    CloseHandle(h);
    return ok;
}

static int in_winpe(void)
{
    char sys[MAX_PATH];
    if (GetWindowsDirectoryA(sys, sizeof(sys)) == 0)
        return 0;
    if (sys[0] == 'X' || sys[0] == 'Y')
        return 1;
    {
        char drv[4] = { 'X', ':', '\\', 0 };
        UINT t = GetDriveTypeA(drv);
        if (t == DRIVE_RAMDISK)
            return 1;
    }
    return 0;
}

static const char *fmt_size(unsigned long long sz)
{
    static char b[4][32];
    static int i = 0;
    double d = (double)sz;
    i = (i + 1) & 3;
    if (d >= 1073741824.0)
        snprintf(b[i], sizeof(b[i]), "%.2f GB", d / 1073741824.0);
    else if (d >= 1048576.0)
        snprintf(b[i], sizeof(b[i]), "%.2f MB", d / 1048576.0);
    else if (d >= 1024.0)
        snprintf(b[i], sizeof(b[i]), "%.1f KB", d / 1024.0);
    else
        snprintf(b[i], sizeof(b[i]), "%llu B", sz);
    return b[i];
}

static const char *attr_str(DWORD a)
{
    static char buf[8];
    buf[0] = (a & FILE_ATTRIBUTE_READONLY)  ? 'R' : 'r';
    buf[1] = (a & FILE_ATTRIBUTE_HIDDEN)    ? 'H' : 'h';
    buf[2] = (a & FILE_ATTRIBUTE_SYSTEM)    ? 'S' : 's';
    buf[3] = (a & FILE_ATTRIBUTE_ARCHIVE)   ? 'A' : 'a';
    buf[4] = (a & FILE_ATTRIBUTE_REPARSE_POINT) ? 'L' : '-';
    buf[5] = (a & FILE_ATTRIBUTE_OFFLINE)   ? 'O' : '-';
    buf[6] = 0;
    return buf;
}

static void print_file_time(const FILETIME *ft)
{
    FILETIME lt;
    SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(ft, &lt)) return;
    if (!FileTimeToSystemTime(&lt, &st)) return;
    printf("%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
}

/* Simple case-insensitive wildcard matcher: '*' and '?' */
static int wmatch(const char *s, const char *p)
{
    while (*p) {
        if (*p == '*') {
            while (p[1] == '*') p++;
            if (p[1] == '\0') return 1;
            for (; *s; s++)
                if (wmatch(s, p + 1)) return 1;
            return 0;
        } else if (*p == '?') {
            if (!*s) return 0;
            s++; p++;
        } else {
            if (tolower((unsigned char)*s) != tolower((unsigned char)*p)) return 0;
            s++; p++;
        }
    }
    return *s == '\0';
}

/* Turn a possibly-relative path into an absolute path. */
static void resolve_path(const char *in, char *out, size_t n)
{
    char cur[MAX_PATH];
    if (in == NULL || *in == '\0') {
        GetCurrentDirectoryA((DWORD)n, out);
        return;
    }
    if (in[0] == '\\' || in[0] == '/') {
        GetCurrentDirectoryA(sizeof(cur), cur);
        snprintf(out, n, "%c:%s", cur[0], in);
        return;
    }
    if (strchr(in, ':') != NULL) {
        snprintf(out, n, "%s", in);
        return;
    }
    GetCurrentDirectoryA(sizeof(cur), cur);
    snprintf(out, n, "%s\\%s", cur, in);
}

/* ============================================================================
 * 2.  Mini Explorer  (file-system commands)
 * ==========================================================================*/

static void cmd_ls(int argc, char **argv)
{
    char path[MAX_PATH], pat[MAX_PATH + 4];
    WIN32_FIND_DATAA find;
    HANDLE h;
    unsigned long long total = 0, files = 0, dirs = 0;

    if (argc >= 3) resolve_path(argv[2], path, sizeof(path));
    else GetCurrentDirectoryA(sizeof(path), path);

    printf("  Directory   : %s\n\n", path);
    snprintf(pat, sizeof(pat), "%s\\*", path);
    h = FindFirstFileA(pat, &find);
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [!] Cannot open directory: %s\n", path);
        return;
    }
    do {
        unsigned long long sz;
        if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, ".."))
            continue;
        sz = ((unsigned long long)find.nFileSizeHigh << 32) | find.nFileSizeLow;
        printf("  [%s] %s %10s  ",
               (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "D" : "F",
               attr_str(find.dwFileAttributes), fmt_size(sz));
        print_file_time(&find.ftLastWriteTime);
        printf("  %s\n", find.cFileName);
        if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) dirs++;
        else { files++; total += sz; }
    } while (FindNextFileA(h, &find) != 0);
    FindClose(h);
    printf("\n  %llu file(s), %llu folder(s), %s total\n", files, dirs, fmt_size(total));
}

static void tree_walk(const char *dir, int depth, unsigned long long *fc, unsigned long long *dc)
{
    WIN32_FIND_DATAA find;
    HANDLE h;
    char pat[MAX_PATH + 8], full[MAX_PATH + 8];
    int i;

    if (depth > 8) return;
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    h = FindFirstFileA(pat, &find);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, "..")) continue;
        for (i = 0; i < depth; i++) printf("    ");
        printf("%s%s%s\n",
               (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "[D] " : "[F] ",
               find.cFileName,
               (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "\\" : "");
        snprintf(full, sizeof(full), "%s\\%s", dir, find.cFileName);
        if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            (*dc)++;
            tree_walk(full, depth + 1, fc, dc);
        } else {
            (*fc)++;
        }
    } while (FindNextFileA(h, &find) != 0);
    FindClose(h);
}

static void cmd_tree(int argc, char **argv)
{
    char path[MAX_PATH];
    unsigned long long fc = 0, dc = 0;
    if (argc >= 3) resolve_path(argv[2], path, sizeof(path));
    else GetCurrentDirectoryA(sizeof(path), path);
    printf("  Tree        : %s\n\n", path);
    tree_walk(path, 0, &fc, &dc);
    printf("\n  %llu file(s), %llu folder(s)\n", fc, dc);
}

static void find_walk(const char *dir, const char *mask, unsigned long long *found)
{
    WIN32_FIND_DATAA find;
    HANDLE h;
    char pat[MAX_PATH + 8], full[MAX_PATH + 8];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    h = FindFirstFileA(pat, &find);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, "..")) continue;
        snprintf(full, sizeof(full), "%s\\%s", dir, find.cFileName);
        if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            find_walk(full, mask, found);
        else if (wmatch(find.cFileName, mask)) {
            printf("  %s\n", full);
            (*found)++;
        }
    } while (FindNextFileA(h, &find) != 0);
    FindClose(h);
}

static void cmd_find(int argc, char **argv)
{
    char root[MAX_PATH], mask[MAX_PATH];
    unsigned long long found = 0;
    if (argc < 3) { printf("  Usage: find <root> [mask]\n"); return; }
    resolve_path(argv[2], root, sizeof(root));
    if (argc >= 4) snprintf(mask, sizeof(mask), "%s", argv[3]);
    else snprintf(mask, sizeof(mask), "*");
    printf("  Searching '%s' mask '%s'\n\n", root, mask);
    find_walk(root, mask, &found);
    printf("\n  %llu match(es)\n", found);
}

static void delete_tree(const char *path)
{
    WIN32_FIND_DATAA find;
    HANDLE h;
    char pat[MAX_PATH + 8], full[MAX_PATH + 8];
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(path);
        return;
    }
    snprintf(pat, sizeof(pat), "%s\\*", path);
    h = FindFirstFileA(pat, &find);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, "..")) continue;
            snprintf(full, sizeof(full), "%s\\%s", path, find.cFileName);
            delete_tree(full);
        } while (FindNextFileA(h, &find) != 0);
        FindClose(h);
    }
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryA(path);
}

static void cmd_del(int argc, char **argv)
{
    char path[MAX_PATH];
    DWORD attr;
    if (argc < 3) { printf("  Usage: del <path>\n"); return; }
    resolve_path(argv[2], path, sizeof(path));
    attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { printf("  [!] Not found: %s\n", path); return; }
    if (!is_admin())
        printf("  (note) You may need Administrator rights.\n");
    delete_tree(path);
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
        printf("  Deleted    : %s\n", path);
    else
        printf("  [!] Could not fully remove: %s\n", path);
}

static void copy_tree(const char *src, const char *dst)
{
    WIN32_FIND_DATAA find;
    HANDLE h;
    char spat[MAX_PATH + 8], sfull[MAX_PATH + 8], dfull[MAX_PATH + 8];
    DWORD attr = GetFileAttributesA(src);
    if (attr == INVALID_FILE_ATTRIBUTES) return;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        CopyFileA(src, dst, FALSE);
        return;
    }
    CreateDirectoryA(dst, NULL);
    snprintf(spat, sizeof(spat), "%s\\*", src);
    h = FindFirstFileA(spat, &find);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, "..")) continue;
            snprintf(sfull, sizeof(sfull), "%s\\%s", src, find.cFileName);
            snprintf(dfull, sizeof(dfull), "%s\\%s", dst, find.cFileName);
            copy_tree(sfull, dfull);
        } while (FindNextFileA(h, &find) != 0);
        FindClose(h);
    }
}

static void cmd_copy(int argc, char **argv)
{
    char src[MAX_PATH], dst[MAX_PATH];
    DWORD attr;
    if (argc < 4) { printf("  Usage: copy <src> <dst>\n"); return; }
    resolve_path(argv[2], src, sizeof(src));
    resolve_path(argv[3], dst, sizeof(dst));
    attr = GetFileAttributesA(src);
    if (attr == INVALID_FILE_ATTRIBUTES) { printf("  [!] Source not found\n"); return; }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) copy_tree(src, dst);
    else if (!CopyFileA(src, dst, FALSE)) printf("  [!] Copy failed (error %lu)\n", GetLastError());
    printf("  Copied     : %s -> %s\n", src, dst);
}

static void cmd_move(int argc, char **argv)
{
    char src[MAX_PATH], dst[MAX_PATH];
    if (argc < 4) { printf("  Usage: move <src> <dst>\n"); return; }
    resolve_path(argv[2], src, sizeof(src));
    resolve_path(argv[3], dst, sizeof(dst));
    if (!MoveFileExA(src, dst, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING))
        printf("  [!] Move failed (error %lu)\n", GetLastError());
    else
        printf("  Moved      : %s -> %s\n", src, dst);
}

static void cmd_mkdir(int argc, char **argv)
{
    char path[MAX_PATH];
    if (argc < 3) { printf("  Usage: mkdir <path>\n"); return; }
    resolve_path(argv[2], path, sizeof(path));
    if (CreateDirectoryA(path, NULL)) printf("  Created    : %s\n", path);
    else printf("  [!] Failed (error %lu)\n", GetLastError());
}

static void cmd_rmdir(int argc, char **argv)
{
    char path[MAX_PATH];
    if (argc < 3) { printf("  Usage: rmdir <path>\n"); return; }
    resolve_path(argv[2], path, sizeof(path));
    if (RemoveDirectoryA(path)) printf("  Removed (empty): %s\n", path);
    else printf("  [!] Failed: not empty or error %lu\n", GetLastError());
}

static void cmd_attr(int argc, char **argv)
{
    char path[MAX_PATH];
    DWORD attr;
    if (argc < 4) { printf("  Usage: attr <h|s|r|a> <path>\n"); return; }
    resolve_path(argv[3], path, sizeof(path));
    attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { printf("  [!] Not found\n"); return; }
    switch (tolower((unsigned char)argv[2][0])) {
        case 'h': attr ^= FILE_ATTRIBUTE_HIDDEN;   break;
        case 's': attr ^= FILE_ATTRIBUTE_SYSTEM;   break;
        case 'r': attr ^= FILE_ATTRIBUTE_READONLY; break;
        case 'a': attr ^= FILE_ATTRIBUTE_ARCHIVE;  break;
        default:  printf("  [!] Unknown flag: %s\n", argv[2]); return;
    }
    if (SetFileAttributesA(path, attr)) printf("  Attributes updated: %s\n", path);
    else printf("  [!] Failed (error %lu)\n", GetLastError());
}

/* Secure erase: overwrite file with zeros, then delete. */
static void cmd_wiper(int argc, char **argv)
{
    unsigned char buf[65536];
    DWORD w;
    HANDLE h;
    LARGE_INTEGER li;
    unsigned long long left;
    char path[MAX_PATH];
    if (argc < 3) { printf("  Usage: wiper <path>\n"); return; }
    resolve_path(argv[2], path, sizeof(path));
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("  [!] Cannot open: %s\n", path); return; }
    GetFileSizeEx(h, &li);
    left = (unsigned long long)li.QuadPart;
    printf("  Wiping %s (%s)...\n", path, fmt_size(left));
    memset(buf, 0, sizeof(buf));
    while (left > 0) {
        DWORD chunk = (left > sizeof(buf)) ? (DWORD)sizeof(buf) : (DWORD)left;
        if (!WriteFile(h, buf, chunk, &w, NULL)) break;
        left -= w;
    }
    SetEndOfFile(h);
    CloseHandle(h);
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    DeleteFileA(path);
    printf("  Overwritten and deleted.\n");
}

/* ============================================================================
 * 3.  Mini task manager  (process commands)
 * ==========================================================================*/

static const char *priority_str(DWORD cls)
{
    switch (cls) {
        case REALTIME_PRIORITY_CLASS:        return "REALTIME";
        case HIGH_PRIORITY_CLASS:            return "HIGH";
        case ABOVE_NORMAL_PRIORITY_CLASS:    return "ABOVE_NORMAL";
        case NORMAL_PRIORITY_CLASS:          return "NORMAL";
        case BELOW_NORMAL_PRIORITY_CLASS:    return "BELOW_NORMAL";
        case IDLE_PRIORITY_CLASS:            return "IDLE";
        default:                             return "?";
    }
}

static void cmd_ps(int argc, char **argv)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    printf("  PID      PPID    Class      Memory      Name\n");
    printf("  ---------------------------------------------------------------\n");
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { printf("  [!] Snapshot failed\n"); return; }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            DWORD cls = NORMAL_PRIORITY_CLASS;
            SIZE_T ws = 0;
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hp) {
                PROCESS_MEMORY_COUNTERS pmc;
                cls = GetPriorityClass(hp);
                if (GetProcessMemoryInfo(hp, &pmc, sizeof(pmc)))
                    ws = pmc.WorkingSetSize;
                CloseHandle(hp);
            }
            printf("  %-8lu  %-6lu  %-11s  %6s  %ws\n",
                   (unsigned long)pe.th32ProcessID,
                   (unsigned long)pe.th32ParentProcessID,
                   priority_str(cls),
                   fmt_size((unsigned long long)ws),
                   pe.szExeFile);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

static DWORD resolve_pid(const char *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    DWORD pid = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char nb[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nb, sizeof(nb), NULL, NULL);
            if (_stricmp(nb, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void cmd_kill(int argc, char **argv)
{
    DWORD pid;
    char *end;
    if (argc < 3) { printf("  Usage: kill <pid|name>\n"); return; }
    pid = strtoul(argv[2], &end, 10);
    if (*end != 0) pid = resolve_pid(argv[2]);
    if (pid == 0) { printf("  [!] Process not found\n"); return; }
    if (!is_admin()) printf("  (note) elevation may be required\n");
    {
        HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hp && TerminateProcess(hp, 1))
            printf("  Terminated PID %lu\n", pid);
        else
            printf("  [!] Failed to terminate PID %lu (error %lu)\n", pid, GetLastError());
        if (hp) CloseHandle(hp);
    }
}

static void cmd_task(int argc, char **argv)
{
    DWORD pid;
    char *end;
    char path[MAX_PATH];
    HANDLE snap, hp;
    PROCESSENTRY32W pe;
    if (argc < 3) { printf("  Usage: task <pid|name>\n"); return; }
    pid = strtoul(argv[2], &end, 10);
    if (*end != 0) pid = resolve_pid(argv[2]);
    if (pid == 0) { printf("  [!] Process not found\n"); return; }

    hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    printf("  PID       : %lu\n", pid);
    if (hp) {
        DWORD sz = sizeof(path);
        SIZE_T ws = 0;
        PROCESS_MEMORY_COUNTERS pmc;
        DWORD cls = GetPriorityClass(hp);
        if (QueryFullProcessImageNameA(hp, 0, path, &sz))
            printf("  Image     : %s\n", path);
        else
            printf("  Image     : (access denied / protected)\n");
        if (GetProcessMemoryInfo(hp, &pmc, sizeof(pmc))) ws = pmc.WorkingSetSize;
        printf("  Priority  : %s\n", priority_str(cls));
        printf("  WorkingSet: %s\n", fmt_size((unsigned long long)ws));
        CloseHandle(hp);
    }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    DWORD sid = 0;
                    ProcessIdToSessionId(pid, &sid);
                    printf("  Name      : %ws\n", pe.szExeFile);
                    printf("  PPID      : %lu\n", (unsigned long)pe.th32ParentProcessID);
                    printf("  Threads   : %lu\n", (unsigned long)pe.cntThreads);
                    printf("  Sess      : %lu\n", (unsigned long)sid);
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
}

static void cmd_priority(int argc, char **argv)
{
    DWORD pid, cls;
    char *end;
    HANDLE hp;
    if (argc < 4) { printf("  Usage: priority <pid|name> <idle|low|normal|high|rt>\n"); return; }
    pid = strtoul(argv[2], &end, 10);
    if (*end != 0) pid = resolve_pid(argv[2]);
    if (!_stricmp(argv[3], "idle"))      cls = IDLE_PRIORITY_CLASS;
    else if (!_stricmp(argv[3], "low"))  cls = BELOW_NORMAL_PRIORITY_CLASS;
    else if (!_stricmp(argv[3], "normal")) cls = NORMAL_PRIORITY_CLASS;
    else if (!_stricmp(argv[3], "high")) cls = HIGH_PRIORITY_CLASS;
    else if (!_stricmp(argv[3], "rt"))   cls = REALTIME_PRIORITY_CLASS;
    else { printf("  [!] Unknown level\n"); return; }
    if (pid == 0) { printf("  [!] Process not found\n"); return; }
    hp = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hp && SetPriorityClass(hp, cls)) printf("  Priority set on PID %lu\n", pid);
    else printf("  [!] Failed (error %lu)\n", GetLastError());
    if (hp) CloseHandle(hp);
}

/* suspend / resume every thread of a process */
static void thread_action(DWORD pid, BOOL suspend)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    DWORD done = 0;
    if (snap == INVALID_HANDLE_VALUE) { printf("  [!] Snapshot failed\n"); return; }
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE th;
            if (te.th32OwnerProcessID != pid) continue;
            th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!th) continue;
            if (suspend) SuspendThread(th); else ResumeThread(th);
            CloseHandle(th);
            done++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    printf("  %s %lu thread(s) of PID %lu\n", suspend ? "Suspended" : "Resumed", done, pid);
}

static void cmd_suspend(int argc, char **argv)
{
    DWORD pid; char *end;
    if (argc < 3) { printf("  Usage: suspend <pid|name>\n"); return; }
    pid = strtoul(argv[2], &end, 10);
    if (*end != 0) pid = resolve_pid(argv[2]);
    if (pid == 0) { printf("  [!] Process not found\n"); return; }
    thread_action(pid, TRUE);
}

static void cmd_resume(int argc, char **argv)
{
    DWORD pid; char *end;
    if (argc < 3) { printf("  Usage: resume <pid|name>\n"); return; }
    pid = strtoul(argv[2], &end, 10);
    if (*end != 0) pid = resolve_pid(argv[2]);
    if (pid == 0) { printf("  [!] Process not found\n"); return; }
    thread_action(pid, FALSE);
}

static void cmd_parent(int argc, char **argv)
{
    DWORD pid; char *end;
    HANDLE snap;
    PROCESSENTRY32W pe;
    if (argc < 3) { printf("  Usage: parent <pid|name>\n"); return; }
    pid = strtoul(argv[2], &end, 10);
    if (*end != 0) pid = resolve_pid(argv[2]);
    if (pid == 0) { printf("  [!] Process not found\n"); return; }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                printf("  PID %lu parent is PID %lu\n", pid, (unsigned long)pe.th32ParentProcessID);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

/* ============================================================================
 * 4.  Services & drivers
 * ==========================================================================*/

static const char *start_type_str(DWORD t)
{
    switch (t) {
        case SERVICE_BOOT_START:   return "BOOT";
        case SERVICE_SYSTEM_START: return "SYSTEM";
        case SERVICE_AUTO_START:   return "AUTO";
        case SERVICE_DEMAND_START: return "MANUAL";
        case SERVICE_DISABLED:     return "DISABLED";
        default:                   return "?";
    }
}

static const char *svc_state_str(DWORD s)
{
    switch (s) {
        case SERVICE_STOPPED:  return "STOPPED";
        case SERVICE_START_PENDING: return "START_PENDING";
        case SERVICE_STOP_PENDING:  return "STOP_PENDING";
        case SERVICE_RUNNING:  return "RUNNING";
        case SERVICE_CONTINUE_PENDING: return "CONT_PENDING";
        case SERVICE_PAUSE_PENDING:   return "PAUSE_PENDING";
        case SERVICE_PAUSED:   return "PAUSED";
        default:               return "?";
    }
}

static SC_HANDLE svc_mgr_open(void)
{
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!m) {
        printf("  [!] Cannot open Service Control Manager (elevation needed). Error %lu\n",
               GetLastError());
        return NULL;
    }
    return m;
}

static void print_svc_table(SC_HANDLE mgr, DWORD type, DWORD state)
{
    DWORD bytes = 0, needed = 0, count = 0, resume = 0;
    LPENUM_SERVICE_STATUS_PROCESSA arr;
    DWORD i;
    EnumServicesStatusExA(mgr, SC_ENUM_PROCESS_INFO, type, state,
                          NULL, 0, &needed, &count, &resume, NULL);
    if (needed == 0) { printf("  (none)\n"); return; }
    arr = (LPENUM_SERVICE_STATUS_PROCESSA)malloc(needed + 1024);
    if (!arr) return;
    resume = 0;
    if (!EnumServicesStatusExA(mgr, SC_ENUM_PROCESS_INFO, type, state,
                               (LPBYTE)arr, needed + 1024, &needed, &count, &resume, NULL)) {
        printf("  [!] Enumeration failed\n");
        free(arr);
        return;
    }
    for (i = 0; i < count; i++) {
        DWORD st = SERVICE_DEMAND_START;
        SC_HANDLE s = OpenServiceA(mgr, arr[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (s) {
            DWORD n = 0;
            LPQUERY_SERVICE_CONFIGA cfg;
            QueryServiceConfigA(s, NULL, 0, &n);
            cfg = (LPQUERY_SERVICE_CONFIGA)malloc(n);
            if (cfg) {
                if (QueryServiceConfigA(s, cfg, n, &n)) st = cfg->dwStartType;
                free(cfg);
            }
            CloseServiceHandle(s);
        }
        printf("  %-28s %-4s %-12s %-8lu %s\n",
               arr[i].lpServiceName,
               start_type_str(st),
               svc_state_str(arr[i].ServiceStatusProcess.dwCurrentState),
               (unsigned long)arr[i].ServiceStatusProcess.dwProcessId,
               arr[i].lpDisplayName);
    }
    free(arr);
}

static void cmd_services(int argc, char **argv)
{
    SC_HANDLE m = svc_mgr_open();
    if (!m) return;
    printf("  NAME                          START  STATE        PID      DISPLAY NAME\n");
    printf("  -----------------------------------------------------------------------------\n");
    print_svc_table(m, SERVICE_WIN32, SERVICE_STATE_ALL);
    CloseServiceHandle(m);
}

static void cmd_drivers(int argc, char **argv)
{
    SC_HANDLE m = svc_mgr_open();
    if (!m) return;
    printf("  DRIVER                        START  STATE      DISPLAY NAME\n");
    printf("  -------------------------------------------------------------------\n");
    print_svc_table(m, SERVICE_DRIVER, SERVICE_STATE_ALL);
    CloseServiceHandle(m);
}

static void cmd_sconfig(int argc, char **argv)
{
    SC_HANDLE m, s;
    LPQUERY_SERVICE_CONFIGA cfg;
    DWORD n = 0;
    if (argc < 3) { printf("  Usage: sconfig <name>\n"); return; }
    m = svc_mgr_open();
    if (!m) return;
    s = OpenServiceA(m, argv[2], SERVICE_QUERY_CONFIG);
    if (!s) { printf("  [!] Service not found\n"); CloseServiceHandle(m); return; }
    QueryServiceConfigA(s, NULL, 0, &n);
    cfg = (LPQUERY_SERVICE_CONFIGA)malloc(n);
    if (cfg && QueryServiceConfigA(s, cfg, n, &n)) {
        printf("  Name        : %s\n", argv[2]);
        printf("  Display     : %s\n", cfg->lpDisplayName);
        printf("  Start type  : %s\n", start_type_str(cfg->dwStartType));
        printf("  State       : %s\n", svc_state_str(cfg->dwServiceType & SERVICE_STATE_ALL));
        printf("  Binary path : %s\n", cfg->lpBinaryPathName);
        printf("  Account     : %s\n", cfg->lpServiceStartName);
        printf("  Error ctrl  : %lu\n", (unsigned long)cfg->dwErrorControl);
    }
    if (cfg) free(cfg);
    CloseServiceHandle(s);
    CloseServiceHandle(m);
}

static void svc_do(int argc, char **argv, int what)
{
    SC_HANDLE m, s;
    SERVICE_STATUS ss;
    if (argc < 3) {
        printf("  Usage: %s <name>\n", what == 0 ? "sstart" : what == 1 ? "sstop" : "sdelete");
        return;
    }
    m = svc_mgr_open();
    if (!m) return;
    s = OpenServiceA(m, argv[2],
                     what == 0 ? SERVICE_START :
                     what == 1 ? SERVICE_STOP : DELETE);
    if (!s) { printf("  [!] Service not found: %s\n", argv[2]); CloseServiceHandle(m); return; }
    if (what == 0) {
        if (StartServiceA(s, 0, NULL)) printf("  Service started: %s\n", argv[2]);
        else printf("  [!] Start failed (error %lu)\n", GetLastError());
    } else if (what == 1) {
        if (ControlService(s, SERVICE_CONTROL_STOP, &ss)) printf("  Service stopping: %s\n", argv[2]);
        else printf("  [!] Stop failed (error %lu)\n", GetLastError());
    } else {
        if (DeleteService(s)) printf("  Service deleted: %s\n", argv[2]);
        else printf("  [!] Delete failed (error %lu)\n", GetLastError());
    }
    CloseServiceHandle(s);
    CloseServiceHandle(m);
}

static void cmd_sstart(int argc, char **argv)  { svc_do(argc, argv, 0); }
static void cmd_sstop(int argc, char **argv)   { svc_do(argc, argv, 1); }
static void cmd_sdelete(int argc, char **argv) { svc_do(argc, argv, 2); }

static void cmd_drvinfo(int argc, char **argv)
{
    /* reuse sconfig-style output for drivers */
    cmd_sconfig(argc, argv);
}

/* ============================================================================
 * 5.  Registry operator
 * ==========================================================================*/

static HKEY parse_root(const char *path, const char **sub)
{
    static const struct { const char *p; HKEY k; } R[] = {
        { "HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
        { "HKEY_CURRENT_USER",  HKEY_CURRENT_USER },
        { "HKEY_CLASSES_ROOT",  HKEY_CLASSES_ROOT },
        { "HKEY_USERS",         HKEY_USERS },
        { "HKEY_CURRENT_CONFIG",HKEY_CURRENT_CONFIG },
        { "HKLM", HKEY_LOCAL_MACHINE },
        { "HKCU", HKEY_CURRENT_USER },
        { "HKCR", HKEY_CLASSES_ROOT },
        { "HKU",  HKEY_USERS },
        { "HKCC", HKEY_CURRENT_CONFIG },
    };
    int i;
    for (i = 0; i < (int)(sizeof(R) / sizeof(R[0])); i++) {
        size_t n = strlen(R[i].p);
        if (_strnicmp(path, R[i].p, n) == 0) {
            const char *s = path + n;
            while (*s == '\\' || *s == '/') s++;
            *sub = s;
            return R[i].k;
        }
    }
    return NULL;
}

static const char *reg_type_name(DWORD t)
{
    switch (t) {
        case REG_SZ:          return "REG_SZ";
        case REG_EXPAND_SZ:   return "REG_EXPAND_SZ";
        case REG_MULTI_SZ:    return "REG_MULTI_SZ";
        case REG_BINARY:      return "REG_BINARY";
        case REG_DWORD:       return "REG_DWORD";
        case REG_DWORD_BIG_ENDIAN: return "REG_DWORD_BIG_ENDIAN";
        case REG_QWORD:       return "REG_QWORD";
        case REG_NONE:        return "REG_NONE";
        default:              return "?";
    }
}

static void cmd_reglist(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    DWORD i = 0;
    char name[1024];
    DWORD n;
    if (argc < 3) { printf("  Usage: reglist <keypath>\n"); return; }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive. Use HKLM\\, HKCU\\, HKCR\\, HKU\\, HKCC\\\n"); return; }
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("  [!] Cannot open key\n");
        return;
    }
    printf("  Subkeys of %s:\n", argv[2]);
    for (;;) {
        n = sizeof(name);
        if (RegEnumKeyExA(hk, i, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        printf("    %s\n", name);
        i++;
    }
    printf("  (%lu subkey(s))\n", i);
    RegCloseKey(hk);
}

static void cmd_regvalues(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    DWORD i = 0;
    char name[4096];
    DWORD n, type, size, isz;
    unsigned char *data;
    if (argc < 3) { printf("  Usage: regvalues <keypath>\n"); return; }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive\n"); return; }
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("  [!] Cannot open key\n");
        return;
    }
    printf("  Values of %s:\n", argv[2]);
    for (;;) {
        n = sizeof(name);
        size = 0;
        type = 0;
        if (RegEnumValueA(hk, i, name, &n, NULL, &type, NULL, &size) != ERROR_SUCCESS) break;
        data = (unsigned char *)malloc(size + 1);
        if (data) {
            isz = size + 1;
            if (RegQueryValueExA(hk, name, NULL, &type, data, &isz) == ERROR_SUCCESS) {
                data[isz] = 0;
                if (type == REG_SZ || type == REG_EXPAND_SZ)
                    printf("  %-32s %-12s \"%s\"\n", name, reg_type_name(type), (char *)data);
                else if (type == REG_DWORD && isz >= 4)
                    printf("  %-32s %-12s 0x%08lx (%lu)\n", name, reg_type_name(type),
                           (unsigned long)(*(DWORD *)data), (unsigned long)(*(DWORD *)data));
                else if (type == REG_QWORD && isz >= 8)
                    printf("  %-32s %-12s 0x%016llx\n", name, reg_type_name(type),
                           (unsigned long long)(*(unsigned long long *)data));
                else {
                    unsigned int j;
                    printf("  %-32s %-12s (%lu bytes) ", name, reg_type_name(type),
                           (unsigned long)isz);
                    for (j = 0; j < isz && j < 32; j++) printf("%02x ", data[j]);
                    printf("\n");
                }
            }
            free(data);
        }
        i++;
    }
    printf("  (%lu value(s))\n", i);
    RegCloseKey(hk);
}

static void cmd_regread(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    DWORD type = 0, size = 0;
    unsigned char *data;
    const char *valname;
    if (argc < 3) { printf("  Usage: regread <keypath> [valuename]\n"); return; }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive\n"); return; }
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("  [!] Cannot open key\n");
        return;
    }
    valname = (argc >= 4) ? argv[3] : "";
    if (RegQueryValueExA(hk, valname, NULL, &type, NULL, &size) != ERROR_SUCCESS) {
        printf("  [!] Value not found\n");
        RegCloseKey(hk);
        return;
    }
    data = (unsigned char *)malloc(size + 1);
    if (data) {
        DWORD isz = size + 1;
        if (RegQueryValueExA(hk, valname, NULL, &type, data, &isz) == ERROR_SUCCESS) {
            data[isz] = 0;
            if (type == REG_SZ || type == REG_EXPAND_SZ)
                printf("  %s = \"%s\"  [%s]\n", valname, (char *)data, reg_type_name(type));
            else if (type == REG_DWORD && isz >= 4)
                printf("  %s = 0x%08lx (%lu)  [%s]\n", valname,
                       (unsigned long)(*(DWORD *)data), (unsigned long)(*(DWORD *)data),
                       reg_type_name(type));
            else {
                unsigned int j;
                printf("  %s = ", valname);
                for (j = 0; j < isz; j++) printf("%02x ", data[j]);
                printf(" [%s, %lu bytes]\n", reg_type_name(type), (unsigned long)isz);
            }
        }
        free(data);
    }
    RegCloseKey(hk);
}

static void cmd_regwrite(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    DWORD type;
    char *end;
    if (argc < 6) {
        printf("  Usage: regwrite <keypath> <valuename> <REG_SZ|REG_DWORD|REG_QWORD|REG_BINARY> <data>\n");
        return;
    }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive\n"); return; }
    if (RegCreateKeyExA(root, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS) {
        printf("  [!] Cannot create/open key\n");
        return;
    }
    if (_stricmp(argv[4], "REG_SZ") == 0 || _stricmp(argv[4], "REG_EXPAND_SZ") == 0) {
        type = (_stricmp(argv[4], "REG_EXPAND_SZ") == 0) ? REG_EXPAND_SZ : REG_SZ;
        RegSetValueExA(hk, argv[3], 0, type, (const BYTE *)argv[5], (DWORD)strlen(argv[5]) + 1);
    } else if (_stricmp(argv[4], "REG_DWORD") == 0) {
        DWORD v = (DWORD)strtoul(argv[5], &end, 0);
        RegSetValueExA(hk, argv[3], 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    } else if (_stricmp(argv[4], "REG_QWORD") == 0) {
        unsigned long long v = (unsigned long long)_strtoui64(argv[5], &end, 0);
        RegSetValueExA(hk, argv[3], 0, REG_QWORD, (const BYTE *)&v, sizeof(v));
    } else {
        printf("  [!] Unsupported type\n");
        RegCloseKey(hk);
        return;
    }
    printf("  Written %s\\%s\n", argv[2], argv[3]);
    RegCloseKey(hk);
}

/* delete all values and subkeys below an open key */
static void clear_key(HKEY hk)
{
    char name[1024];
    DWORD n;
    HKEY c;
    for (;;) {
        n = sizeof(name);
        if (RegEnumValueA(hk, 0, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        RegDeleteValueA(hk, name);
    }
    for (;;) {
        n = sizeof(name);
        if (RegEnumKeyExA(hk, 0, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (RegOpenKeyExA(hk, name, 0, KEY_READ | KEY_WRITE, &c) == ERROR_SUCCESS) {
            clear_key(c);
            RegCloseKey(c);
        }
        RegDeleteKeyA(hk, name);
    }
}

static void cmd_regdel(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    if (argc < 3) { printf("  Usage: regdel <keypath>\n"); return; }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive\n"); return; }
    if (RegOpenKeyExA(root, sub, 0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) {
        printf("  [!] Cannot open key\n");
        return;
    }
    clear_key(hk);
    RegCloseKey(hk);
    if (RegDeleteKeyA(root, sub) == ERROR_SUCCESS)
        printf("  Key deleted: %s\n", argv[2]);
    else
        printf("  [!] Delete failed (error %lu)\n", GetLastError());
}

static void cmd_regdelval(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    if (argc < 4) { printf("  Usage: regdelval <keypath> <valuename>\n"); return; }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive\n"); return; }
    if (RegOpenKeyExA(root, sub, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) {
        printf("  [!] Cannot open key\n");
        return;
    }
    if (RegDeleteValueA(hk, argv[3]) == ERROR_SUCCESS)
        printf("  Value deleted: %s\n", argv[3]);
    else
        printf("  [!] Delete failed (error %lu)\n", GetLastError());
    RegCloseKey(hk);
}

static void reg_walk(HKEY hk, const char *path, const char *term, int depth)
{
    char name[1024];
    char full[4096];
    DWORD n, type, size;
    unsigned char *data;
    DWORD i = 0;
    HKEY c;

    if (depth > 8) return;
    for (;;) {
        n = sizeof(name);
        size = 0;
        if (RegEnumValueA(hk, i, name, &n, NULL, &type, NULL, &size) != ERROR_SUCCESS) break;
        data = (unsigned char *)malloc(size + 1);
        if (data) {
            DWORD isz = size + 1;
            if (RegQueryValueExA(hk, name, NULL, &type, data, &isz) == ERROR_SUCCESS) {
                if (isz > size) isz = size;
                data[isz] = 0;
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    if (strstr((char *)data, term) || strstr(name, term))
                        printf("  %s\\%s = \"%s\"\n", path, name, (char *)data);
                } else if (strstr(name, term)) {
                    printf("  %s\\%s  [%s]\n", path, name, reg_type_name(type));
                }
            }
            free(data);
        }
        i++;
    }
    i = 0;
    for (;;) {
        n = sizeof(name);
        if (RegEnumKeyExA(hk, i, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        snprintf(full, sizeof(full), "%s\\%s", path, name);
        if (RegOpenKeyExA(hk, name, 0, KEY_READ, &c) == ERROR_SUCCESS) {
            reg_walk(c, full, term, depth + 1);
            RegCloseKey(c);
        }
        i++;
    }
}

static void cmd_regsearch(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    if (argc < 4) { printf("  Usage: regsearch <keypath> <text>\n"); return; }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive\n"); return; }
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("  [!] Cannot open key\n");
        return;
    }
    printf("  Searching registry under %s for \"%s\"\n", argv[2], argv[3]);
    reg_walk(hk, argv[2], argv[3], 0);
    RegCloseKey(hk);
}

static void reg_dump(HKEY hk, const char *path, int depth)
{
    char name[1024], full[4096];
    DWORD n, type, size;
    unsigned char *data;
    DWORD i = 0;
    HKEY c;

    printf("\n[HKEY_LOCAL_MACHINE\\%s]\n", path);   /* dump format simplified */
    for (;;) {
        n = sizeof(name);
        size = 0;
        if (RegEnumValueA(hk, i, name, &n, NULL, &type, NULL, &size) != ERROR_SUCCESS) break;
        data = (unsigned char *)malloc(size + 1);
        if (data) {
            DWORD isz = size + 1;
            if (RegQueryValueExA(hk, name, NULL, &type, data, &isz) == ERROR_SUCCESS) {
                if (isz > size) isz = size;
                data[isz] = 0;
                if (type == REG_SZ || type == REG_EXPAND_SZ)
                    printf("\"%s\"=\"%s\"\n", name, (char *)data);
                else if (type == REG_DWORD && isz >= 4)
                    printf("\"%s\"=dword:%08lx\n", name, (unsigned long)(*(DWORD *)data));
                else if (type == REG_QWORD && isz >= 8)
                    printf("\"%s\"=hex(b):%08llx\n", name,
                           (unsigned long long)(*(unsigned long long *)data));
                else {
                    unsigned int j;
                    printf("\"%s\"=hex:", name);
                    for (j = 0; j < isz; j++) printf("%02x%s", data[j], (j + 1 < isz) ? "," : "");
                    printf("\n");
                }
            }
            free(data);
        }
        i++;
    }
    i = 0;
    for (;;) {
        n = sizeof(name);
        if (RegEnumKeyExA(hk, i, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        snprintf(full, sizeof(full), "%s\\%s", path, name);
        if (RegOpenKeyExA(hk, name, 0, KEY_READ, &c) == ERROR_SUCCESS) {
            reg_dump(c, full, depth + 1);
            RegCloseKey(c);
        }
        i++;
    }
}

static void cmd_regdump(int argc, char **argv)
{
    const char *sub;
    HKEY root, hk;
    if (argc < 3) { printf("  Usage: regdump <keypath>\n"); return; }
    root = parse_root(argv[2], &sub);
    if (!root) { printf("  [!] Bad hive\n"); return; }
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("  [!] Cannot open key\n");
        return;
    }
    reg_dump(hk, sub, 0);
    RegCloseKey(hk);
}

/* ============================================================================
 * 6.  Autostart editor
 * ==========================================================================*/

static void print_run_key(const char *title, HKEY root, const char *sub)
{
    HKEY hk;
    DWORD i = 0;
    char name[4096];
    DWORD n, type, size;
    printf("  --- %s  (%s)\n", title, sub);
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("      (not present)\n");
        return;
    }
    for (;;) {
        unsigned char *data;
        n = sizeof(name);
        size = 0;
        if (RegEnumValueA(hk, i, name, &n, NULL, &type, NULL, &size) != ERROR_SUCCESS) break;
        data = (unsigned char *)malloc(size + 1);
        if (data) {
            DWORD isz = size + 1;
            int susp = 0;
            if (RegQueryValueExA(hk, name, NULL, &type, data, &isz) == ERROR_SUCCESS) {
                if (isz > size) isz = size;
                data[isz] = 0;
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    if (strstr((char *)data, "\\Temp\\") ||
                        strstr((char *)data, "%TEMP%") || strstr((char *)data, "%temp%"))
                        susp = 1;
                    printf("      %-40s %s\n", name, susp ? "[!] " : "");
                    printf("          -> %s\n", (char *)data);
                } else {
                    printf("      %-40s [%s]\n", name, reg_type_name(type));
                }
            }
            free(data);
        }
        i++;
    }
    RegCloseKey(hk);
}

static void print_startup_folder(const char *title, const char *dir)
{
    WIN32_FIND_DATAA find;
    HANDLE h;
    char pat[MAX_PATH + 8];
    printf("  --- %s  (%s)\n", title, dir);
    if (dir[0] == 0) { printf("      (not available)\n"); return; }
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    h = FindFirstFileA(pat, &find);
    if (h == INVALID_HANDLE_VALUE) { printf("      (empty / not found)\n"); return; }
    do {
        if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, "..")) continue;
        printf("      %s\n", find.cFileName);
    } while (FindNextFileA(h, &find) != 0);
    FindClose(h);
}

static void cmd_autoruns(int argc, char **argv)
{
    char startup[MAX_PATH], common_startup[MAX_PATH];
    int show_all = (argc >= 3) ? 1 : 0;
    (void)show_all;
    printf("\n  === AUTOSTART REPORT ===\n\n");

    print_run_key("HKCU Run", HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    print_run_key("HKCU RunOnce", HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    print_run_key("HKLM Run", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    print_run_key("HKLM RunOnce", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    print_run_key("HKLM Policies\\Explorer\\Run", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    print_run_key("HKCU Policies\\Explorer\\Run", HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    print_run_key("Winlogon Userinit/Shell", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");

    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, startup);
    SHGetFolderPathA(NULL, CSIDL_COMMON_STARTUP, NULL, SHGFP_TYPE_CURRENT, common_startup);
    print_startup_folder("Startup folder (user)", startup);
    print_startup_folder("Startup folder (common)", common_startup);

    printf("\n  Auto-start services (START=AUTO):\n");
    {
        SC_HANDLE m = svc_mgr_open();
        if (m) {
            print_svc_table(m, SERVICE_WIN32, SERVICE_STATE_ALL);
            CloseServiceHandle(m);
        }
    }
    printf("  (Use 'services' / 'drivers' for the full list)\n");
}

static void cmd_astartup(int argc, char **argv)
{
    char startup[MAX_PATH], common_startup[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, startup);
    SHGetFolderPathA(NULL, CSIDL_COMMON_STARTUP, NULL, SHGFP_TYPE_CURRENT, common_startup);
    print_startup_folder("Startup folder (user)", startup);
    print_startup_folder("Startup folder (common)", common_startup);
}

static void cmd_areg(int argc, char **argv)
{
    print_run_key("HKCU Run", HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    print_run_key("HKCU RunOnce", HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    print_run_key("HKLM Run", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    print_run_key("HKLM RunOnce", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    print_run_key("Winlogon", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
}

static void cmd_aservice(int argc, char **argv)
{
    SC_HANDLE m = svc_mgr_open();
    if (!m) return;
    printf("  Auto-start services:\n");
    print_svc_table(m, SERVICE_WIN32, SERVICE_STATE_ALL);
    CloseServiceHandle(m);
}

static void cmd_adriver(int argc, char **argv)
{
    SC_HANDLE m = svc_mgr_open();
    if (!m) return;
    printf("  Boot/System drivers:\n");
    print_svc_table(m, SERVICE_DRIVER, SERVICE_STATE_ALL);
    CloseServiceHandle(m);
}

static void cmd_atask(int argc, char **argv)
{
    printf("  Scheduled tasks (via schtasks):\n");
    system("schtasks /query /fo LIST /nh 2>nul");
}

/* ============================================================================
 * 7.  System integrity & protection
 * ==========================================================================*/

static void check_essential_files(void)
{
    static const char *files[] = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "ws2_32.dll", "crypt32.dll",
        "cmd.exe", "services.exe", "lsass.exe", "csrss.exe",
        "winload.exe", NULL
    };
    char sys[MAX_PATH];
    int i, bad = 0;
    GetSystemDirectoryA(sys, sizeof(sys));
    printf("  Essential files under %s:\n", sys);
    for (i = 0; files[i]; i++) {
        char full[MAX_PATH + 16];
        DWORD attr;
        snprintf(full, sizeof(full), "%s\\%s", sys, files[i]);
        attr = GetFileAttributesA(full);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            printf("    [MISSING] %s\n", files[i]);
            bad++;
        } else {
            printf("    [OK]      %s\n", files[i]);
        }
    }
    if (bad) printf("  !!! %d essential file(s) missing - possible corruption or infection.\n", bad);
    else    printf("  All checked system files are present.\n");
}

static void check_winlogon(void)
{
    HKEY hk;
    DWORD type, size;
    char buf[4096];
    const char *sub = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        static const char *vals[] = { "Userinit", "Shell", "UIHost", NULL };
        int i;
        printf("  Winlogon entries:\n");
        for (i = 0; vals[i]; i++) {
            size = sizeof(buf) - 1;
            type = 0;
            buf[0] = 0;
            if (RegQueryValueExA(hk, vals[i], NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS) {
                buf[size] = 0;
                printf("    %-8s = %s\n", vals[i], buf);
            }
        }
        RegCloseKey(hk);
    }
}

static void cmd_integrity(int argc, char **argv)
{
    char sys[MAX_PATH];
    char sfc[MAX_PATH + 16];
    printf("  === SYSTEM INTEGRITY CHECK ===\n\n");
    printf("  Environment   : %s\n", in_winpe() ? "Windows Recovery (WinPE)" : "Normal Windows");
    printf("  Administrator : %s\n\n", is_admin() ? "yes" : "no (run elevated for full check)");

    check_essential_files();
    printf("\n");
    check_winlogon();
    printf("\n");

    GetSystemDirectoryA(sys, sizeof(sys));
    snprintf(sfc, sizeof(sfc), "%s\\sfc.exe", sys);
    if (GetFileAttributesA(sfc) != INVALID_FILE_ATTRIBUTES) {
        printf("  Running 'sfc /verifyonly' (System File Checker)...\n");
        system("\"C:\\Windows\\System32\\sfc.exe\" /verifyonly");
    } else {
        printf("  sfc.exe is not available in this environment (normal in WinPE).\n");
    }
}

/* analyse hosts file for suspicious redirections */
static void scan_hosts(void)
{
    char hosts[MAX_PATH + 64];
    char sys[MAX_PATH];
    FILE *f;
    char line[1024];
    GetSystemDirectoryA(sys, sizeof(sys));
    snprintf(hosts, sizeof(hosts), "%s\\drivers\\etc\\hosts", sys);
    f = fopen(hosts, "r");
    if (!f) { printf("    [INFO] hosts file not readable.\n"); return; }
    printf("    Hosts file: %s\n", hosts);
    while (fgets(line, sizeof(line), f)) {
        char *p = line, *q;
        char ip[64], host[512];
        int suspicious = 0;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0) continue;
        q = p;
        while (*q && *q != ' ' && *q != '\t') q++;
        {
            size_t l = (size_t)(q - p);
            if (l < sizeof(ip)) { memcpy(ip, p, l); ip[l] = 0; } else ip[0] = 0;
        }
        while (*q == ' ' || *q == '\t') q++;
        {
            char *e = q;
            while (*e && *e != '\n' && *e != '\r') e++;
            {
                size_t l = (size_t)(e - q);
                if (l < sizeof(host)) { memcpy(host, q, l); host[l] = 0; } else host[0] = 0;
            }
        }
        if (strcmp(ip, "127.0.0.1") != 0 && strcmp(ip, "::1") != 0 && strcmp(ip, "0.0.0.0") != 0)
            suspicious = 1;
        if (suspicious)
            printf("    [!] REDIRECT %s -> %s\n", host, ip);
        else if (host[0])
            printf("    [ ] %s -> %s\n", host, ip);
    }
    fclose(f);
}

static void cmd_scan(int argc, char **argv)
{
    int suspicious_total = 0;
    HANDLE snap;
    PROCESSENTRY32W pe;
    printf("  === QUICK THREAT SCAN ===\n\n");

    printf("  1) Hosts file redirections:\n");
    scan_hosts();
    printf("\n");

    printf("  2) Running processes launched from TEMP / suspicious folders:\n");
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                char path[MAX_PATH];
                DWORD sz = sizeof(path);
                HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                        pe.th32ProcessID);
                if (hp) {
                    if (QueryFullProcessImageNameA(hp, 0, path, &sz)) {
                        if (strstr(path, "\\Temp\\") || strstr(path, "\\TEMP\\")) {
                            printf("    [!] %ws  ->  %s\n", pe.szExeFile, path);
                            suspicious_total++;
                        }
                    }
                    CloseHandle(hp);
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (suspicious_total == 0) printf("    (nothing suspicious found)\n");

    printf("\n  3) Unusual autostart locations:\n");
    print_run_key("HKCU Run", HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    print_run_key("HKLM Run", HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");

    printf("\n  Scan complete. %d suspicious item(s) flagged.\n", suspicious_total);
    printf("  Use 'autoruns' for the full autostart picture.\n");
}

static void cmd_secpolicy(int argc, char **argv)
{
    HKEY hk;
    DWORD type, size, val;
    printf("  === SECURITY POLICY DIAGNOSTIC ===\n\n");
    printf("  --- UAC (LUA) ---\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        static const char *v[] = { "EnableLUA", "ConsentPromptBehaviorAdmin",
                                   "PromptOnSecureDesktop", "ValidateAdminCodeSignatures",
                                   "FilterAdministratorToken", "DisableCAD" };
        int i;
        for (i = 0; i < (int)(sizeof(v) / sizeof(v[0])); i++) {
            size = sizeof(val);
            type = 0;
            val = 0;
            if (RegQueryValueExA(hk, v[i], NULL, &type, (LPBYTE)&val, &size) == ERROR_SUCCESS)
                printf("    %-30s = %lu\n", v[i], (unsigned long)val);
            else
                printf("    %-30s = (not set)\n", v[i]);
        }
        RegCloseKey(hk);
    }
    printf("  --- LSA ---\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        static const char *v[] = { "RestrictAnonymous", "RestrictAnonymousSAM",
                                   "LimitBlankPasswordUse", "CrashOnAuditFail",
                                   "RunAsPPL" };
        int i;
        for (i = 0; i < (int)(sizeof(v) / sizeof(v[0])); i++) {
            size = sizeof(val);
            type = 0;
            val = 0;
            if (RegQueryValueExA(hk, v[i], NULL, &type, (LPBYTE)&val, &size) == ERROR_SUCCESS)
                printf("    %-30s = %lu\n", v[i], (unsigned long)val);
            else
                printf("    %-30s = (not set)\n", v[i]);
        }
        RegCloseKey(hk);
    }
    printf("  --- Legal notice ---\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        char buf[1024];
        size = sizeof(buf);
        if (RegQueryValueExA(hk, "LegalNoticeText", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
            printf("    LegalNoticeText = %s\n", buf);
        else
            printf("    LegalNoticeText = (not set)\n");
        RegCloseKey(hk);
    }
}

static void cmd_bootconfig(int argc, char **argv)
{
    printf("  Boot configuration (BCD) - read-only view:\n\n");
    system("bcdedit /enum 2>nul");
    printf("  (if empty, bcdedit is unavailable here)\n");
}

static void cmd_hosts(int argc, char **argv)
{
    char hosts[MAX_PATH + 64];
    char sys[MAX_PATH];
    FILE *f;
    char line[1024];
    GetSystemDirectoryA(sys, sizeof(sys));
    snprintf(hosts, sizeof(hosts), "%s\\drivers\\etc\\hosts", sys);
    printf("  Hosts file: %s\n\n", hosts);
    f = fopen(hosts, "r");
    if (!f) { printf("  [!] Cannot read hosts file\n"); return; }
    while (fgets(line, sizeof(line), f))
        fputs(line, stdout);
    fclose(f);
}

static void cmd_lsa(int argc, char **argv)
{
    HKEY hk;
    DWORD type, size, val = 0;
    printf("  LSA protection (RunAsPPL):\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        size = sizeof(val);
        if (RegQueryValueExA(hk, "RunAsPPL", NULL, &type, (LPBYTE)&val, &size) == ERROR_SUCCESS)
            printf("    RunAsPPL = %lu  (%s)\n", (unsigned long)val,
                   val ? "LSA protection ENABLED" : "LSA protection DISABLED");
        else
            printf("    RunAsPPL = (not set)  - not protected\n");
        RegCloseKey(hk);
    }
}

static void cmd_safeboot(int argc, char **argv)
{
    const char *branches[] = {
        "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal",
        "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network"
    };
    int b;
    for (b = 0; b < 2; b++) {
        HKEY hk;
        DWORD i = 0;
        char name[512];
        printf("  SafeBoot %s:\n", b == 0 ? "Minimal" : "Network");
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, branches[b], 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            for (;;) {
                DWORD n = sizeof(name);
                if (RegEnumKeyExA(hk, i, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                printf("    %s\n", name);
                i++;
            }
            RegCloseKey(hk);
        } else {
            printf("    (not present)\n");
        }
    }
}

/* ============================================================================
 * 8.  Network
 * ==========================================================================*/

static const char *tcp_state_str(DWORD s)
{
    switch (s) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_ESTAB: return "ESTAB";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        default: return "?";
    }
}

static void cmd_netstat(int argc, char **argv)
{
    ULONG size = 0;
    MIB_TCPTABLE_OWNER_PID *t;
    MIB_UDPTABLE_OWNER_PID *u;
    DWORD i;

    printf("  TCP connections:\n");
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    t = (MIB_TCPTABLE_OWNER_PID *)malloc(size ? size : 1);
    if (t && GetExtendedTcpTable(t, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (i = 0; i < t->dwNumEntries; i++) {
            struct in_addr ia;
            ia.S_un.S_addr = t->table[i].dwLocalAddr;
            printf("    TCP  %-21s:%u  %-9s  PID %lu\n",
                   inet_ntoa(ia),
                   (unsigned)(t->table[i].dwLocalPort & 0xffff),
                   tcp_state_str(t->table[i].dwState),
                   (unsigned long)t->table[i].dwOwningPid);
        }
    }
    if (t) free(t);

    printf("\n  UDP connections:\n");
    size = 0;
    GetExtendedUdpTable(NULL, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    u = (MIB_UDPTABLE_OWNER_PID *)malloc(size ? size : 1);
    if (u && GetExtendedUdpTable(u, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (i = 0; i < u->dwNumEntries; i++) {
            struct in_addr ia;
            ia.S_un.S_addr = u->table[i].dwLocalAddr;
            printf("    UDP  %-21s:%u  PID %lu\n",
                   inet_ntoa(ia),
                   (unsigned)(u->table[i].dwLocalPort & 0xffff),
                   (unsigned long)u->table[i].dwOwningPid);
        }
    }
    if (u) free(u);
    printf("\n  (Use 'task <pid>' to identify a process.)\n");
}

static void cmd_proxy(int argc, char **argv)
{
    HKEY hk;
    DWORD type, size;
    printf("  Internet proxy settings (HKCU):\n");
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("    (cannot read)\n");
        return;
    }
    {
        DWORD v = 0;
        size = sizeof(v);
        if (RegQueryValueExA(hk, "ProxyEnable", NULL, &type, (LPBYTE)&v, &size) == ERROR_SUCCESS)
            printf("    ProxyEnable = %lu\n", (unsigned long)v);
        else
            printf("    ProxyEnable = (not set)\n");
    }
    {
        char buf[1024];
        buf[0] = 0;
        size = sizeof(buf);
        if (RegQueryValueExA(hk, "ProxyServer", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
            printf("    ProxyServer = %s\n", buf);
        else
            printf("    ProxyServer = (not set)\n");
        buf[0] = 0;
        size = sizeof(buf);
        if (RegQueryValueExA(hk, "AutoConfigURL", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
            printf("    AutoConfigURL = %s\n", buf);
    }
    RegCloseKey(hk);
}

static void cmd_dns(int argc, char **argv)
{
    HKEY hk;
    DWORD i = 0;
    char name[512];
    const char *base = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
    printf("  DNS configuration per interface:\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, base, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("    (cannot read)\n");
        return;
    }
    for (;;) {
        HKEY c;
        DWORD n = sizeof(name);
        if (RegEnumKeyExA(hk, i, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (RegOpenKeyExA(hk, name, 0, KEY_READ, &c) == ERROR_SUCCESS) {
            char buf[2048];
            DWORD size, type;
            printf("    Interface %s:\n", name);
            buf[0] = 0; size = sizeof(buf);
            if (RegQueryValueExA(c, "NameServer", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
                printf("      NameServer    = %s\n", buf);
            buf[0] = 0; size = sizeof(buf);
            if (RegQueryValueExA(c, "DhcpNameServer", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
                printf("      DHCP DNS      = %s\n", buf);
            RegCloseKey(c);
        }
        i++;
    }
    RegCloseKey(hk);
}

/* ============================================================================
 * 9.  Security status
 * ==========================================================================*/

static DWORD svc_state(const char *name)
{
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    SC_HANDLE s;
    SERVICE_STATUS ss;
    DWORD st = 0;
    if (!m) return 0;
    s = OpenServiceA(m, name, SERVICE_QUERY_STATUS);
    if (s) {
        if (QueryServiceStatus(s, &ss)) st = ss.dwCurrentState;
        CloseServiceHandle(s);
    }
    CloseServiceHandle(m);
    return st;
}

static void cmd_uac(int argc, char **argv)
{
    HKEY hk;
    DWORD type, size, v = 0;
    printf("  UAC (User Account Control):\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        size = sizeof(v);
        if (RegQueryValueExA(hk, "EnableLUA", NULL, &type, (LPBYTE)&v, &size) == ERROR_SUCCESS)
            printf("    EnableLUA = %lu (%s)\n", (unsigned long)v,
                   v ? "UAC ENABLED" : "UAC DISABLED - risk of silent infection");
        else
            printf("    EnableLUA = (not set)\n");
        RegCloseKey(hk);
    }
}

static void cmd_defender(int argc, char **argv)
{
    DWORD st = svc_state("WinDefend");
    HKEY hk;
    DWORD type, size, v = 0;
    printf("  Windows Defender:\n");
    if (st)
        printf("    Service state = %s\n", svc_state_str(st));
    else
        printf("    Service 'WinDefend' not present (normal in WinPE).\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows Defender\\Policy",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        size = sizeof(v);
        if (RegQueryValueExA(hk, "DisableAntiSpyware", NULL, &type, (LPBYTE)&v, &size) == ERROR_SUCCESS)
            printf("    DisableAntiSpyware = %lu %s\n", (unsigned long)v,
                   v ? "[!] Defender is disabled by policy" : "");
        RegCloseKey(hk);
    }
}

static void cmd_firewall(int argc, char **argv)
{
    DWORD st = svc_state("MpsSvc");
    HKEY hk;
    DWORD type, size, v = 0;
    const char *prof[] = { "StandardProfile", "DomainProfile", "PublicProfile" };
    int i;
    printf("  Windows Firewall:\n");
    if (st)
        printf("    Service (MpsSvc) = %s\n", svc_state_str(st));
    else
        printf("    Service 'MpsSvc' not present (normal in WinPE).\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        for (i = 0; i < 3; i++) {
            HKEY p;
            char sub[128];
            snprintf(sub, sizeof(sub), "%s", prof[i]);
            if (RegOpenKeyExA(hk, sub, 0, KEY_READ, &p) == ERROR_SUCCESS) {
                size = sizeof(v);
                if (RegQueryValueExA(p, "EnableFirewall", NULL, &type, (LPBYTE)&v, &size) == ERROR_SUCCESS)
                    printf("    %-16s = %lu (%s)\n", prof[i], (unsigned long)v,
                           v ? "ON" : "OFF");
                RegCloseKey(p);
            }
        }
        RegCloseKey(hk);
    }
}

static void cmd_updates(int argc, char **argv)
{
    DWORD st = svc_state("wuauserv");
    HKEY hk;
    DWORD type, size, v = 0;
    printf("  Windows Update:\n");
    if (st)
        printf("    Service (wuauserv) = %s\n", svc_state_str(st));
    else
        printf("    Service 'wuauserv' not present (normal in WinPE).\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        size = sizeof(v);
        if (RegQueryValueExA(hk, "AUOptions", NULL, &type, (LPBYTE)&v, &size) == ERROR_SUCCESS)
            printf("    AUOptions = %lu\n", (unsigned long)v);
        RegCloseKey(hk);
    }
}

/* ============================================================================
 * 10.  Recovery environment (WinPE) commands
 * ==========================================================================*/

static void cmd_winpe(int argc, char **argv)
{
    char sys[MAX_PATH];
    char win[MAX_PATH];
    DWORD n;
    printf("  Recovery environment check:\n");
    n = GetSystemDirectoryA(sys, sizeof(sys));
    printf("    System dir   : %s\n", sys);
    n = GetWindowsDirectoryA(win, sizeof(win));
    printf("    Windows dir  : %s\n", win);
    printf("    Environment  : %s\n", in_winpe() ? "WINPE (recovery)" : "Normal OS");
    printf("    RAMDISK      : %s\n",
           GetDriveTypeA("X:\\") == DRIVE_RAMDISK ? "yes (X: is RAM disk)" : "no");
    printf("    Administrator: %s\n", is_admin() ? "yes" : "no");
}

static void cmd_mountcheck(int argc, char **argv)
{
    DWORD mask = GetLogicalDrives();
    int i;
    printf("  Mounted volumes:\n");
    for (i = 0; i < 26; i++) {
        char root[4], vol[256], fs[64];
        DWORD serial, maxlen, flags;
        UINT type;
        ULARGE_INTEGER t, f;
        if (!(mask & (1 << i))) continue;
        root[0] = (char)('A' + i); root[1] = ':'; root[2] = '\\'; root[3] = 0;
        type = GetDriveTypeA(root);
        vol[0] = 0; fs[0] = 0;
        GetVolumeInformationA(root, vol, sizeof(vol), &serial, &maxlen, &flags, fs, sizeof(fs));
        printf("    %s  type=%-8s  fs=%-8s  \"%s\"",
               root,
               type == DRIVE_FIXED ? "FIXED" :
               type == DRIVE_REMOVABLE ? "REMOVABLE" :
               type == DRIVE_CDROM ? "CD-ROM" :
               type == DRIVE_RAMDISK ? "RAMDISK" :
               type == DRIVE_REMOTE ? "NETWORK" : "?",
               fs[0] ? fs : "-", vol);
        if (type == DRIVE_FIXED && GetDiskFreeSpaceExA(root, &f, &t, NULL))
            printf("  %s free / %s total", fmt_size(f.QuadPart), fmt_size(t.QuadPart));
        printf("\n");
    }
}

/* ============================================================================
 * 11.  Info / version / help
 * ==========================================================================*/

typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOW *);

static void cmd_info(int argc, char **argv)
{
    OSVERSIONINFOW vi;
    MEMORYSTATUSEX ms;
    SYSTEM_INFO si;
    char cn[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cns = sizeof(cn);
    HKEY hk;
    char prod[256];
    const char *arch = "";

    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    {
        HMODULE ntd = GetModuleHandleA("ntdll.dll");
        RtlGetVersion_t rv = (RtlGetVersion_t)GetProcAddress(ntd, "RtlGetVersion");
        if (rv) rv(&vi);
    }
    printf("  === SYSTEM INFORMATION ===\n\n");
    printf("  OS version   : Windows %lu.%lu.%lu",
           (unsigned long)vi.dwMajorVersion, (unsigned long)vi.dwMinorVersion,
           (unsigned long)vi.dwBuildNumber);
    if (in_winpe()) printf("  (recovery env)");
    printf("\n");
    prod[0] = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD type = 0, size = sizeof(prod) - 1;
        if (RegQueryValueExA(hk, "ProductName", NULL, &type, (LPBYTE)prod, &size) == ERROR_SUCCESS)
            prod[size] = 0;
        RegCloseKey(hk);
    }
    printf("  Product      : %s\n", prod[0] ? prod : "?");
    if (GetComputerNameA(cn, &cns))
        printf("  Computer     : %s\n", cn);
    {
        char ab[64];
        GetEnvironmentVariableA("PROCESSOR_ARCHITECTURE", ab, sizeof(ab));
        printf("  Architecture : %s\n", ab);
    }
    GetSystemInfo(&si);
    printf("  Processors   : %lu (online)\n", (unsigned long)si.dwNumberOfProcessors);
    ZeroMemory(&ms, sizeof(ms));
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        printf("  Memory       : %s free / %s total\n",
               fmt_size((unsigned long long)ms.ullAvailPhys),
               fmt_size((unsigned long long)ms.ullTotalPhys));
    printf("  Administrator: %s\n", is_admin() ? "yes" : "no");
    printf("  Environment  : %s\n", in_winpe() ? "WINPE" : "Normal OS");
}

static void cmd_version(int argc, char **argv)
{
    printf("  TildaUnlocker v%s  (c) ExEintel\n", APP_VER);
    printf("  Anti-malware & system hygiene utility\n");
    printf("  Windows 10/11, also runs in WinPE (recovery environment).\n");
}

static void cmd_help(int argc, char **argv)
{
    printf(
        "\n"
        "  TildaUnlocker v%s  -  Anti-malware & system hygiene utility  (c) ExEintel\n"
        "\n"
        "  Call schema:  tildaunlocker.exe  <command>  [parameters]\n"
        "\n"
        "  ==== 1. Mini Explorer (file system)  ====\n"
        "    ls <path>              List directory contents\n"
        "    tree <path>            Show directory tree\n"
        "    find <root> [mask]     Search for files (masks: * ?)\n"
        "    del <path>             Delete file or folder (recursive)\n"
        "    copy <src> <dst>       Copy file or folder\n"
        "    move <src> <dst>       Move file or folder\n"
        "    mkdir <path>           Create directory\n"
        "    rmdir <path>           Remove empty directory\n"
        "    attr <h|s|r|a> <path>  Toggle Hidden/System/ReadOnly/Archive\n"
        "    wiper <path>           Secure-erase file (overwrite + delete)\n"
        "\n"
        "  ==== 2. Mini task manager (processes)  ====\n"
        "    ps                     List running processes\n"
        "    task <pid|name>        Show process details\n"
        "    kill <pid|name>        Terminate a process\n"
        "    priority <pid> <level> Set priority (idle|low|normal|high|rt)\n"
        "    suspend <pid|name>     Suspend all threads of a process\n"
        "    resume <pid|name>      Resume all threads of a process\n"
        "    parent <pid|name>      Show parent process\n"
        "\n"
        "  ==== 3. Services & drivers  ====\n"
        "    services                List services\n"
        "    sconfig <name>          Show service configuration\n"
        "    sstart <name>           Start a service\n"
        "    sstop <name>            Stop a service\n"
        "    sdelete <name>          Delete a service\n"
        "    drivers                 List device drivers\n"
        "    drvinfo <name>          Show driver details\n"
        "\n"
        "  ==== 4. Registry operator  ====\n"
        "    reglist <key>           List subkeys\n"
        "    regvalues <key>         List values\n"
        "    regread <key> [value]   Read a value\n"
        "    regwrite <key> <name> <REG_SZ|REG_DWORD|REG_QWORD> <data>   Write value\n"
        "    regdel <key>            Delete key (recursive)\n"
        "    regdelval <key> <name>  Delete a value\n"
        "    regsearch <key> <text>  Search a subtree for text\n"
        "    regdump <key>           Dump key tree as text\n"
        "    Keys: HKLM\\, HKCU\\, HKCR\\, HKU\\, HKCC\\\n"
        "\n"
        "  ==== 5. Autostart editor  ====\n"
        "    autoruns                Full autostart report\n"
        "    areg                    Registry Run keys\n"
        "    astartup                Startup folders\n"
        "    aservice                Auto-start services\n"
        "    adriver                 Boot/System drivers\n"
        "    atask                   Scheduled tasks\n"
        "\n"
        "  ==== 6. System integrity & protection  ====\n"
        "    integrity               Check system file integrity\n"
        "    scan                    Quick threat scan\n"
        "    secpolicy               Security policy diagnostic\n"
        "    bootconfig              View boot configuration (BCD)\n"
        "    hosts                   Show hosts file\n"
        "    lsa                     LSA protection status\n"
        "    safeboot                SafeBoot configuration\n"
        "\n"
        "  ==== 7. Network  ====\n"
        "    netstat                 Active TCP/UDP connections\n"
        "    proxy                   Proxy settings\n"
        "    dns                     DNS configuration\n"
        "\n"
        "  ==== 8. Security status  ====\n"
        "    uac                     UAC status\n"
        "    defender                Windows Defender status\n"
        "    firewall                Windows Firewall status\n"
        "    updates                 Windows Update status\n"
        "\n"
        "  ==== 9. Recovery / info  ====\n"
        "    winpe                   Detect recovery environment\n"
        "    mountcheck              List mounted volumes\n"
        "    info                    System information\n"
        "    version                 Program version\n"
        "    help                    This help\n",
        APP_VER);
}

/* ============================================================================
 * 12.  Command dispatcher
 * ==========================================================================*/

static void print_banner(void)
{
    printf(
        "\n"
        "  ============================================================\n"
        "   TildaUnlocker  v%s      (c) ExEintel\n"
        "   Anti-malware & system hygiene utility - Windows 10/11 + WinPE\n"
        "  ============================================================\n",
        APP_VER);
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        void (*fn)(int, char **);
    } cmd[] = {
        { "help",      cmd_help },
        { "version",   cmd_version },
        { "info",      cmd_info },
        /* mini explorer */
        { "ls",        cmd_ls },
        { "dir",       cmd_ls },
        { "tree",      cmd_tree },
        { "find",      cmd_find },
        { "del",       cmd_del },
        { "delete",    cmd_del },
        { "rm",        cmd_del },
        { "copy",      cmd_copy },
        { "move",      cmd_move },
        { "mkdir",     cmd_mkdir },
        { "rmdir",     cmd_rmdir },
        { "attr",      cmd_attr },
        { "wiper",     cmd_wiper },
        /* mini task manager */
        { "ps",        cmd_ps },
        { "tasklist",  cmd_ps },
        { "task",      cmd_task },
        { "kill",      cmd_kill },
        { "priority",  cmd_priority },
        { "suspend",   cmd_suspend },
        { "resume",    cmd_resume },
        { "parent",    cmd_parent },
        /* services & drivers */
        { "services",  cmd_services },
        { "sconfig",   cmd_sconfig },
        { "sstart",    cmd_sstart },
        { "sstop",     cmd_sstop },
        { "sdelete",   cmd_sdelete },
        { "drivers",   cmd_drivers },
        { "drvinfo",   cmd_drvinfo },
        /* registry */
        { "reglist",   cmd_reglist },
        { "regvalues", cmd_regvalues },
        { "regread",   cmd_regread },
        { "regwrite",  cmd_regwrite },
        { "regdel",    cmd_regdel },
        { "regdelval", cmd_regdelval },
        { "regsearch", cmd_regsearch },
        { "regdump",   cmd_regdump },
        /* autostart */
        { "autoruns",  cmd_autoruns },
        { "au",        cmd_autoruns },
        { "areg",      cmd_areg },
        { "astartup",  cmd_astartup },
        { "aservice",  cmd_aservice },
        { "adriver",   cmd_adriver },
        { "atask",     cmd_atask },
        /* integrity & protection */
        { "integrity", cmd_integrity },
        { "scan",      cmd_scan },
        { "secpolicy", cmd_secpolicy },
        { "bootconfig",cmd_bootconfig },
        { "hosts",     cmd_hosts },
        { "lsa",       cmd_lsa },
        { "safeboot",  cmd_safeboot },
        /* network */
        { "netstat",   cmd_netstat },
        { "proxy",     cmd_proxy },
        { "dns",       cmd_dns },
        /* security status */
        { "uac",       cmd_uac },
        { "defender",  cmd_defender },
        { "firewall",  cmd_firewall },
        { "updates",   cmd_updates },
        /* recovery / info */
        { "winpe",     cmd_winpe },
        { "mountcheck",cmd_mountcheck },
    };
    size_t n = sizeof(cmd) / sizeof(cmd[0]);
    size_t i;

    SetConsoleOutputCP(CP_ACP);

    if (argc < 2) {
        print_banner();
        cmd_help(argc, argv);
        return 0;
    }

    if (_stricmp(argv[1], "?" ) == 0 ||
        _stricmp(argv[1], "-h") == 0 ||
        _stricmp(argv[1], "--help") == 0) {
        print_banner();
        cmd_help(argc, argv);
        return 0;
    }

    for (i = 0; i < n; i++) {
        if (_stricmp(argv[1], cmd[i].name) == 0) {
            print_banner();
            cmd[i].fn(argc, argv);
            return 0;
        }
    }

    print_banner();
    printf("  [!] Unknown command: %s\n", argv[1]);
    printf("  Type 'tildaunlocker.exe help' for the full command list.\n");
    return 1;
}
