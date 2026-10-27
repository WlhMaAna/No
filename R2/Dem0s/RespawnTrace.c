#include <stdio.h>
#include <time.h>

int main(void)
{
    const char *log_path = "C:\\Users\\Public\\exe_log.txt";

    FILE *file = fopen(log_path, "a");
    if (file == NULL)
        return 1;

    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);

    if (local_time != NULL)
    {
        char timestamp[64];

        strftime(timestamp, sizeof(timestamp),
                 "%Y-%m-%d %H:%M:%S",
                 local_time);

        fprintf(file, "%s\n", timestamp);
    }

    fclose(file);
    return 0;
}
