#include <windows.h>
#include <fstream>

extern "C" __declspec(dllexport) void* InitializePrintMonitor2(void* pMonitorInit, HANDLE* phMonitor)
{
    return NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        std::ofstream log("C:\\Users\\Public\\portmon_log.txt", std::ios::app);
        if (log.is_open())
        {
            SYSTEMTIME st;
            GetLocalTime(&st);
            log << st.wYear << "-" << st.wMonth << "-" << st.wDay
                << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond
                << " - DLL loaded into spoolsv.exe" << std::endl;
            log.close();
        }
    }
    return TRUE;
}
