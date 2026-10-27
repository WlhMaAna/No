#include <windows.h>
#include <fstream>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    std::ofstream log("C:\\Users\\Public\\scr_log.txt", std::ios::app);
    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        log << st.wYear << "-" << st.wMonth << "-" << st.wDay
            << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond
            << " - Screensaver payload fired" << std::endl;
        log.close();
    }
    return 0;
}
