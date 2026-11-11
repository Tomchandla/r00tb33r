#include <stdio.h>

int main(int argc, char *argv[])
{
    FILE *f = fopen("/tmp/bhclient.log", "a");

    if (f == NULL)
        return 1;

    fprintf(f, "Worker started!\n");
    fprintf(f, "Received the following address: %s\n", argv[1]);
    fclose(f);

    return 0;
}
