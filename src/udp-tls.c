#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define BUFFER_SIZE 16384
#define COOKIE_SECRET_LENGTH 16

static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
static int cookie_initialized = 0;

static int verify_cookie(SSL* ssl,
                         const unsigned char* cookie,
                         unsigned int cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
  } peer;

  /* If secret isn't initialized yet, the cookie can't be valid */
  if (!cookie_initialized)
    return 0;

  /* Read peer information */
  (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
    case AF_INET:
      length += sizeof(struct in_addr);
      break;
    case AF_INET6:
      length += sizeof(struct in6_addr);
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  length += sizeof(in_port_t);
  buffer = (unsigned char*)OPENSSL_malloc(length);

  if (buffer == NULL) {
    fprintf(stderr, "out of memory\n");
    return 0;
  }

  switch (peer.ss.ss_family) {
    case AF_INET:
      memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(in_port_t), &peer.s4.sin_addr,
             sizeof(struct in_addr));
      break;
    case AF_INET6:
      memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr,
             sizeof(struct in6_addr));
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char*)buffer, length, result, &resultlength);
  OPENSSL_free(buffer);

  if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
    return 1;

  return 0;
}

static int generate_cookie(SSL* ssl,
                           unsigned char* cookie,
                           unsigned int* cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
  } peer;

  /* Initialize a random secret */
  if (!cookie_initialized) {
    if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
      fprintf(stderr, "error setting random cookie secret\n");
      return 0;
    }
    cookie_initialized = 1;
  }

  /* Read peer information */
  (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
    case AF_INET:
      length += sizeof(struct in_addr);
      break;
    case AF_INET6:
      length += sizeof(struct in6_addr);
      break;
    default:
      OPENSSL_assert(0);
      break;
  }
  length += sizeof(in_port_t);
  buffer = (unsigned char*)OPENSSL_malloc(length);

  if (buffer == NULL) {
    fprintf(stderr, "out of memory\n");
    return 0;
  }

  switch (peer.ss.ss_family) {
    case AF_INET:
      memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr,
             sizeof(struct in_addr));
      break;
    case AF_INET6:
      memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr,
             sizeof(struct in6_addr));
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char*)buffer, length, result, &resultlength);
  OPENSSL_free(buffer);

  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;

  return 1;
}

static int dtls_verify_callback(int ok, X509_STORE_CTX* ctx) {
  /* This function should ask the user
   * if he trusts the received certificate.
   * Here we always trust.
   */
  return 1;
}

static struct sockaddr_in servaddr;
static struct sockaddr_in cliaddr;
static SSL* ssl;
static void connection_handle() {
  char buf[BUFFER_SIZE];
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf(stderr, "socket creation failed\n");
    exit(EXIT_FAILURE);
  }

  if (bind(fd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
    fprintf(stderr, "bind failed\n");
    exit(EXIT_FAILURE);
  }

  if (connect(fd, (const struct sockaddr*)&cliaddr, sizeof(cliaddr))) {
    fprintf(stderr, "connect failed\n");
    exit(EXIT_FAILURE);
  }

  /* Set new fd and set BIO to connected */
  BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
  BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &cliaddr);

  int ret;
  /* Finish handshake */
  do {
    ret = SSL_accept(ssl);
  } while (ret == 0);
  if (ret < 0) {
    fprintf(stderr, "SSL_accept: %s\n", ERR_error_string(ERR_get_error(), buf));
    goto cleanup;
  }

  /* Set and activate timeouts */
  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
  SSL_get_peer_certificate(ssl);

cleanup:
  close(fd);
  SSL_free(ssl);
}

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

int main(int argc, char** argv) {
  unsigned char buffer[BUFFER_SIZE];

  if (argc < 2) {
    fprintf(stderr, "Error: usage: ./cat filename\n");
    return (-1);
  }

  memset(&cliaddr, 0, sizeof(cliaddr));

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;  // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(atoi(argv[3]));

  const bool is_client = argv[1][0] == 'c';
  const bool is_server = argv[1][0] == 's';
  const bool is_dtls = argv[1][1] == 'd';
  const bool is_udp = argv[1][2] == 'u';
  const bool is_sctp = argv[1][2] == 's';
  SSL_CTX* ctx;
  if (is_dtls) {
    if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) {
      fprintf(stderr, "Warning: OpenSSL version mismatch!\n");
      fprintf(stderr, "Compiled against %s\n", OPENSSL_VERSION_TEXT);
      fprintf(stderr, "Linked against   %s\n",
              OpenSSL_version(OPENSSL_VERSION));

      if (OpenSSL_version_num() >> 20 != OPENSSL_VERSION_NUMBER >> 20) {
        fprintf(stderr,
                "Major and minor version numbers must match, exiting.\n");
        exit(EXIT_FAILURE);
      }
    }

    if (OPENSSL_VERSION_NUMBER < 0x1010102fL) {
      fprintf(
          stderr,
          "Error: %s is unsupported, use OpenSSL Version 1.1.1a or higher\n",
          OpenSSL_version(OPENSSL_VERSION));
      exit(EXIT_FAILURE);
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    if (is_server) {
      ctx = SSL_CTX_new(DTLS_server_method());
    }

    if (is_client) {
      ctx = SSL_CTX_new(DTLS_client_method());
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem",
                                      SSL_FILETYPE_PEM)) {
      fprintf(stderr, "ERROR: no certificate found!\n");
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem",
                                     SSL_FILETYPE_PEM)) {
      fprintf(stderr, "ERROR: no private key found!\n");
    }

    if (!SSL_CTX_check_private_key(ctx)) {
      fprintf(stderr, "ERROR: invalid private key!\n");
    }

    /* Client has to authenticate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                       dtls_verify_callback);

    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
  }

  int type = SOCK_DGRAM;
  int protocol = 0;
  if (is_sctp) {
    type = SOCK_STREAM;
    protocol = IPPROTO_SCTP;
  }

  int fd = socket(AF_INET, type, protocol);
  if (fd < 0) {
    fprintf(stderr, "socket creation failed\n");
    exit(EXIT_FAILURE);
  }

  if (is_server) {
    if (bind(fd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
      fprintf(stderr, "bind failed\n");
      exit(EXIT_FAILURE);
    }

    if (is_sctp) {
      struct sctp_initmsg initmsg = {
          .sinit_num_ostreams = 5,
          .sinit_max_instreams = 5,
          .sinit_max_attempts = 4,
      };

      if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg,
                     sizeof(initmsg)) < 0) {
        fprintf(stderr, "setsockopt failed1\n");
        exit(EXIT_FAILURE);
      }

      fprintf(stderr, "listen failed1\n");
      if (listen(fd, initmsg.sinit_max_instreams) < 0) {
        fprintf(stderr, "listen failed\n");
        exit(EXIT_FAILURE);
      }
      fprintf(stderr, "listen failed2\n");
    }

    socklen_t len = sizeof(cliaddr);
    while (1) {
      int conn_fd;
      if (is_dtls) {
        /* Create BIO */
        BIO* bio = BIO_new_dgram(fd, BIO_NOCLOSE);

        /* Set and activate timeouts */
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        ssl = SSL_new(ctx);

        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        while (DTLSv1_listen(ssl, (BIO_ADDR*)&cliaddr) <= 0)
          ;
        connection_handle();
      } else if (is_udp) {
        ssize_t rf = recvfrom(fd, (unsigned char*)buffer, BUFFER_SIZE,
                              MSG_WAITALL, (struct sockaddr*)&cliaddr, &len);
        if (rf < 1) {
          fprintf(stderr, "recvfrom failed %ld\n", rf);
          exit(EXIT_FAILURE);
        }
      } else if (is_sctp) {
        fprintf(stderr, "accept failed\n");
        conn_fd = accept(fd, (struct sockaddr*)NULL, NULL);
        fprintf(stderr, "accept failed\n");
        if (conn_fd < 0) {
          fprintf(stderr, "accept failed\n");
          exit(EXIT_FAILURE);
        }
      }

      int file = open(argv[4], O_RDWR);
      if (file == -1) {
        fprintf(stderr, "Error: %s: file not found\n", argv[4]);
        return (-1);
      }

      int fsize = get_fsize(file);
      if (fsize < 0) {
        return -1;
      }

      unsigned char* addr =
          mmap(NULL, fsize + 1, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
      if (addr == (void*)-1) {
        fprintf(stderr, "mmap failed, %s\n", strerror(errno));
      }

      int cnt = 0;
      addr[fsize] = (unsigned char)EOF;
      ++fsize;
      for (unsigned char* addri = addr; addri <= &addr[fsize];
           addri += BUFFER_SIZE) {
        ssize_t to_write = addri + BUFFER_SIZE > &addr[fsize]
                               ? &addr[fsize] - addri
                               : BUFFER_SIZE;

#if 0
        if (to_write < BUFFER_SIZE) {
          unsigned char dst[to_write + 1];
          memcpy(dst, addri, to_write);
          ++to_write;
          dst[to_write] = (unsigned char)EOF;
          const ssize_t bytes_written = write(STDOUT_FILENO, dst, to_write);
          if (bytes_written != to_write) {
            fprintf(stderr, "Write failed1 %ld != %ld\n", bytes_written,
                    to_write);
          }
        } else {
#endif

        // const ssize_t bytes_written = write(STDOUT_FILENO, addri, to_write);
        ssize_t bytes_written;
        if (is_udp) {
          bytes_written =
              sendto(fd, (unsigned char*)addri, to_write, MSG_CONFIRM,
                     (const struct sockaddr*)&cliaddr, len);
        } else if (is_sctp) {
          bytes_written = sctp_sendmsg(conn_fd, (unsigned char*)addri, to_write,
                                       NULL, 0, 0, 0, 0, 0, 0);
        }

        printf("Write failed2 %ld != %ld, %s\n", bytes_written, to_write,
               strerror(errno));
        if (bytes_written != to_write) {
          fprintf(stderr, "Write failed2 %ld != %ld, %s\n", bytes_written,
                  to_write, strerror(errno));
        }
        //        }
      }

      int err = munmap(addr, fsize);
      if (err) {
        fprintf(stderr, "munmap error! [%d]\n", err);
      }

      close(file);
    }
  }

  if (is_client) {
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
      perror("Error");
    }

    if (is_udp) {
      const char* hello = "hello";
      sendto(fd, (unsigned char*)hello, strlen(hello), MSG_CONFIRM,
             (const struct sockaddr*)&servaddr, sizeof(servaddr));
    }

    int file = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (file == -1) {
      fprintf(stderr, "Error: %s: file not found\n", argv[4]);
      return (-1);
    }

    ssize_t n;
    do {
      int len;
      if (is_udp) {
        n = recvfrom(fd, (unsigned char*)buffer, BUFFER_SIZE, MSG_WAITALL,
                     (struct sockaddr*)&servaddr, &len);
      } else if (is_sctp) {
        struct sctp_sndrcvinfo sndrcvinfo;
        int flags;
        n = sctp_recvmsg(fd, (unsigned char*)buffer, BUFFER_SIZE, NULL, 0,
                         &sndrcvinfo, &flags);
      }

      if (buffer[n - 1] == (unsigned char)EOF) {
        --n;
      } else if (n < 0) {
        break;
      }

      ssize_t bytes_written = write(file, &buffer, n);
      if (bytes_written != n) {
        fprintf(stderr, "Write failed %ld != %ld\n", bytes_written, n);
      }
    } while (n && buffer[n] != (unsigned char)EOF);

    close(file);
  }

cleanup:
  close(fd);
  SSL_free(ssl);

  return 0;
}
