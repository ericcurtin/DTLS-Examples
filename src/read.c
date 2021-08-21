#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
    print("out of memory\n");
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
      printf("error setting random cookie secret\n");
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
    printf("out of memory\n");
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

int main(int argc, char** argv) {
  unsigned char buffer[BUFFER_SIZE];

  if (argc < 2) {
    fprintf(stderr, "Error: usage: ./cat filename\n");
    return (-1);
  }

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "socket creation failed\n");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;  // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(atoi(argv[3]));
  if (argv[1][1] == 'd') {
    if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) {
      printf("Warning: OpenSSL version mismatch!\n");
      printf("Compiled against %s\n", OPENSSL_VERSION_TEXT);
      printf("Linked against   %s\n", OpenSSL_version(OPENSSL_VERSION));

      if (OpenSSL_version_num() >> 20 != OPENSSL_VERSION_NUMBER >> 20) {
        printf("Major and minor version numbers must match, exiting.\n");
        exit(EXIT_FAILURE);
      }
    }

    if (OPENSSL_VERSION_NUMBER < 0x1010102fL) {
      printf("Error: %s is unsupported, use OpenSSL Version 1.1.1a or higher\n",
             OpenSSL_version(OPENSSL_VERSION));
      exit(EXIT_FAILURE);
    }
  }

  if (argv[1][0] == 's') {
    SSL_CTX* ctx;
    if (argv[1][1] == 'd') {
      OpenSSL_add_ssl_algorithms();
      SSL_load_error_strings();
      ctx = SSL_CTX_new(DTLS_server_method());
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

    if (bind(sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
      fprintf(stderr, "bind failed\n");
      exit(EXIT_FAILURE);
    }

    struct sockaddr_in cliaddr;
    memset(&cliaddr, 0, sizeof(cliaddr));
    socklen_t len = sizeof(cliaddr);
    while (1) {
      ssize_t rf = recvfrom(sockfd, (unsigned char*)buffer, BUFFER_SIZE,
                            MSG_WAITALL, (struct sockaddr*)&cliaddr, &len);
      if (rf < 1) {
        fprintf(stderr, "recvfrom failed %ld\n", rf);
      }

      int file = open(argv[4], O_RDONLY);
      if (file == -1) {
        fprintf(stderr, "Error: %s: file not found\n", argv[4]);
        return (-1);
      }

      ssize_t read_size;
      while ((read_size = read(file, buffer, BUFFER_SIZE)) > 0) {
        if (read_size < BUFFER_SIZE) {
          buffer[read_size] = (unsigned char)EOF;
          ++read_size;
        }

        ssize_t bytes_written =
            sendto(sockfd, (unsigned char*)buffer, read_size, MSG_CONFIRM,
                   (const struct sockaddr*)&cliaddr, len);
        if (bytes_written != read_size) {
          fprintf(stderr, "Write failed %ld != %ld\n", bytes_written,
                  read_size);
        }
      }

      close(file);
    }
  }

  if (argv[1][0] == 'c') {
    const char* hello = "hello";
    sendto(sockfd, (unsigned char*)hello, strlen(hello), MSG_CONFIRM,
           (const struct sockaddr*)&servaddr, sizeof(servaddr));

    ssize_t n;
    do {
      int len;
      n = recvfrom(sockfd, (unsigned char*)buffer, BUFFER_SIZE, MSG_WAITALL,
                   (struct sockaddr*)&servaddr, &len);
      if (buffer[n - 1] == (unsigned char)EOF) {
        --n;
      }

      ssize_t bytes_written = write(STDOUT_FILENO, &buffer, n);
      if (bytes_written != n) {
        fprintf(stderr, "Write failed %ld != %ld\n", bytes_written, n);
      }
    } while (n && buffer[n] != (unsigned char)EOF);
  }

  return 0;
}
