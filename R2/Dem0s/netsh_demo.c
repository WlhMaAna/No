#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        FILE *f = fopen("C:\\Users\\Public\\netsh_demo.txt", "a");

        if (f)
        {
            SYSTEMTIME st;
            GetLocalTime(&st);

            fprintf(
                f,
                "%04d-%02d-%02d %02d:%02d:%02d.%03d - DLL loaded\n",
                st.wYear,
                st.wMonth,
                st.wDay,
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds
            );

            fclose(f);
        }
    }

    return TRUE;
}
