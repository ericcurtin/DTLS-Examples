#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 16384

static inline int get_fsize(int fd) {
  struct stat sb;
  int err;
  err = fstat(fd, &sb);
  if (err) {
    fprintf(stderr, "fstat error! [%s]\n", strerror(errno));
    return -1;
  }

  return sb.st_size;
}

int main(int argc, char* argv[]) {
  unsigned char buffer[BUFFER_SIZE];
  int fd = open(argv[1], O_RDWR);
  if (fd == -1) {
    fprintf(stderr, "Error: %s: file not found\n", argv[1]);
    return (-1);
  }

  int fsize = get_fsize(fd);
  if (fsize < 0) {
    return -1;
  }

  unsigned char* addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  int cnt = 0;
  addr[fsize] = (unsigned char)EOF;
  ++fsize;
  for (unsigned char* addri = addr; addri <= &addr[fsize - 1]; addri += BUFFER_SIZE) {
    const ssize_t to_write = addri + BUFFER_SIZE > &addr[fsize - 1] ? &addr[fsize] - addri : BUFFER_SIZE;
    const ssize_t bytes_written = write(STDOUT_FILENO, addri, to_write);
    if (bytes_written != to_write) {
      fprintf(stderr, "Write failed %ld != %ld\n", bytes_written, to_write);
    }
  }

  int err = munmap(addr, fsize);
  if (err) {
    fprintf(stderr, "munmap error! [%d]\n", err);
  }

#if 0
  ssize_t read_size;
  while ((read_size = read(fd, buffer, BUFFER_SIZE)) > 0) {
    if (read_size < BUFFER_SIZE) {
      buffer[read_size] = (unsigned char)EOF;
      ++read_size;
    }

    ssize_t bytes_written = write(STDOUT_FILENO, buffer, read_size);
    if (bytes_written != read_size) {
      fprintf(stderr, "Write failed %ld != %ld\n", bytes_written, read_size);
    }
  }
#endif

  close(fd);

  return 0;
}
