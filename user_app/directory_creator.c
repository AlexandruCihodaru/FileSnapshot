#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2){
        printf("Usage: dir_creat <path>\n");
        return -EPERM;
    }
    else {
        struct stat st = {0};

        if (stat(argv[1], &st) == -1){
            mkdir(argv[1], 0700);
        }
    }
    return 0;
}
