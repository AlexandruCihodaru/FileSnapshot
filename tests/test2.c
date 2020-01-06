#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>

int main()
{

  size_t bytesWritten =0;
  int fd;
  int PageSize;
  const char *text = "This is a test";

 if ( (PageSize = sysconf(_SC_PAGE_SIZE)) < 0) {
    perror("sysconf() Error=");
    return -1;
 }

 fd = open("/home/acihodaru/Desktop/file.txt",
             (O_CREAT | O_TRUNC | O_RDWR),
             (S_IRWXU | S_IRWXG | S_IRWXO) );
  if ( fd < 0 ) {
    perror("open() error");
    return fd;
  }

  off_t lastoffset = lseek( fd, PageSize, SEEK_SET);
  bytesWritten = write(fd, " ", 1 );
  if (bytesWritten != 1 ) {
    perror("write error. ");
    return -1;
  }


      /* mmap the file. */
  void *address;
  int len;
   off_t my_offset = 0;
   len = PageSize;   /* Map one page */
   address =
        mmap(NULL, len, PROT_WRITE, MAP_SHARED, fd, my_offset);

   if ( address == MAP_FAILED ) {
       perror("mmap error. " );
       return -1;
     }
       /* Move some data into the file using memory map. */
     (void) strcpy( (char*) address, text);
       /* use msync to write changes to disk. */
     if ( msync( address, PageSize , MS_SYNC ) < 0 ) {
          perror("msync failed with error:");
          return -1;
      }
      else (void) printf("%s","msync completed successfully.");

    close(fd);
}
