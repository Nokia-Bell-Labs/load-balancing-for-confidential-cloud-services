/*
 * © 2026 Nokia
 * Licensed under the BSD 3-Clause Clear License
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/*
 * proxy.c — Janus backend DC-TLS termination proxy
 *
 * Runs inside the backend CVM/container.  Accepts TLS 1.3 connections with
 * Delegated Credentials (RFC 9345) on the public port, relays decrypted
 * HTTP to a local app (typically Flask on 127.0.0.1:8080).
 *
 * Loads credentials from the backend's sealed directory
 * (/dev/shm/janus-backend-sealed on a CVM):
 *   frontend_chain.pem        – frontend cert chain (PEM)
 *   delegated_credential.bin  – raw DC bytes (from the frontend)
 *   private_key.pem           – backend's ECDSA P-256 key, generated in the TEE
 *   certificate.pem           – self-signed X.509 cert over the same key
 *                               (non-DC clients; the frontend pins its
 *                               fingerprint for the proxy-mode hop)
 *
 * Registers two credentials with BoringSSL:
 *   1. DC credential (primary) — used when client advertises DC support
 *   2. X.509 fallback — used for non-DC clients
 *
 * Usage:
 *   dc_proxy [--listen PORT] [--backend HOST:PORT | /path/to/unix.sock]
 *            [--sealed-dir DIR] [--x509-cert PEM --x509-key PEM]
 *   (--x509-* serves a plain X.509 leaf instead: the vanilla-TLS baseline)
 *
 * Defaults:
 *   --listen       8443
 *   --backend      127.0.0.1:8080
 *   --sealed-dir   ./sealed
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* ── globals ──────────────────────────────────────────────────────────────── */

static const char *g_listen_port   = "8443";
static const char *g_backend_host  = "127.0.0.1";
static int         g_backend_port  = 8080;
static const char *g_sealed_dir    = "./sealed";
/* Plain-X.509 mode: when set, the proxy terminates TLS with an ordinary
 * certificate+key instead of a Delegated Credential.  This provides a
 * vanilla-TLS baseline on the SAME BoringSSL fork-per-connection data path
 * as the DC terminator, so a vanilla-vs-Janus comparison isolates the
 * attestation overhead rather than the TLS-termination implementation. */
static const char *g_x509_cert     = NULL;
static const char *g_x509_key      = NULL;
static SSL_CREDENTIAL *g_dc_cred   = NULL;
/* Second credential in DC mode: the backend's self-signed X.509 certificate
 * over the same key, served to clients that do not offer Delegated
 * Credentials (the frontend's proxy-mode hop pins its fingerprint). */
static SSL_CREDENTIAL *g_x509_cred = NULL;
/* Live context; rebuilt on SIGHUP after the backend installs a renewed DC
 * (design §4.3: the frontend re-signs DCs when its certificate is renewed). */
static SSL_CTX *g_ctx = NULL;
static volatile sig_atomic_t g_reload = 0;
#include <errno.h>
#include <signal.h>

static void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "[dc_proxy] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    fflush(stdout);
    va_end(ap);
}

static void die(const char *msg)
{
    fprintf(stderr, "[dc_proxy] FATAL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* ── Load a PEM private key ──────────────────────────────────────────────── */

static EVP_PKEY *load_pkey(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    if (!bio) { fprintf(stderr, "Cannot open key %s\n", path); exit(1); }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        fprintf(stderr, "Failed to parse key %s\n", path);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return pkey;
}

/* ── Load a PEM cert chain into CRYPTO_BUFFER array ──────────────────────── */

static size_t load_cert_chain_pem(const char *path, CRYPTO_BUFFER ***out_certs)
{
    BIO *bio = BIO_new_file(path, "rb");
    if (!bio) { fprintf(stderr, "Cannot open cert %s\n", path); exit(1); }

    CRYPTO_BUFFER *tmp[32];
    size_t n = 0;

    for (;;) {
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!cert) break;

        uint8_t *der = NULL;
        int der_len = i2d_X509(cert, &der);
        X509_free(cert);
        if (der_len < 0) break;

        tmp[n] = CRYPTO_BUFFER_new(der, (size_t)der_len, NULL);
        OPENSSL_free(der);
        if (!tmp[n]) die("CRYPTO_BUFFER_new");
        n++;
        if (n >= 32) break;
    }
    BIO_free(bio);

    if (n == 0) { fprintf(stderr, "No certs in %s\n", path); exit(1); }

    *out_certs = malloc(n * sizeof(CRYPTO_BUFFER *));
    memcpy(*out_certs, tmp, n * sizeof(CRYPTO_BUFFER *));
    return n;
}

/* ── Read a file into memory ─────────────────────────────────────────────── */

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "Failed to read %s\n", path);
        exit(1);
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* ── Register DC credential ──────────────────────────────────────────────── */

/* PAPER: §4.3 'DC in Redirection Mode' / §4.4 — the backend presents the frontend certificate + its DC in the TLS Certificate message. */
static void add_dc_credential(SSL_CTX *ctx,
                               CRYPTO_BUFFER **chain, size_t chain_len,
                               const uint8_t *dc_data, size_t dc_len,
                               EVP_PKEY *dc_pkey)
{
    SSL_CREDENTIAL *cred = SSL_CREDENTIAL_new_delegated();
    if (!cred) die("SSL_CREDENTIAL_new_delegated");

    if (!SSL_CREDENTIAL_set1_cert_chain(cred, chain, chain_len))
        die("SSL_CREDENTIAL_set1_cert_chain (DC)");

    CRYPTO_BUFFER *dc_buf = CRYPTO_BUFFER_new(dc_data, dc_len, NULL);
    if (!dc_buf) die("CRYPTO_BUFFER_new for DC");
    int ok = SSL_CREDENTIAL_set1_delegated_credential(cred, dc_buf);
    CRYPTO_BUFFER_free(dc_buf);
    if (!ok) die("SSL_CREDENTIAL_set1_delegated_credential");

    if (!SSL_CREDENTIAL_set1_private_key(cred, dc_pkey))
        die("SSL_CREDENTIAL_set1_private_key (DC)");

    if (!SSL_CTX_add1_credential(ctx, cred))
        die("SSL_CTX_add1_credential (DC)");

    g_dc_cred = cred;
    log_info("DC credential registered (%zu-byte DC)", dc_len);
}

/* ── Register the X.509 fallback credential (non-DC clients) ─────────────── */
/* PAPER: §4.4 Proxy mode — credential for clients without DC support (the frontend's forwarding hop, pinned to this key). */
static void add_x509_credential(SSL_CTX *ctx, const char *cert_path, EVP_PKEY *key)
{
    CRYPTO_BUFFER **chain = NULL;
    size_t n = load_cert_chain_pem(cert_path, &chain);
    if (n == 0) die("load_cert_chain_pem (x509 fallback)");
    SSL_CREDENTIAL *cred = SSL_CREDENTIAL_new_x509();
    if (!cred) die("SSL_CREDENTIAL_new_x509");
    if (!SSL_CREDENTIAL_set1_cert_chain(cred, chain, n))
        die("SSL_CREDENTIAL_set1_cert_chain (x509)");
    if (!SSL_CREDENTIAL_set1_private_key(cred, key))
        die("SSL_CREDENTIAL_set1_private_key (x509)");
    if (!SSL_CTX_add1_credential(ctx, cred))
        die("SSL_CTX_add1_credential (x509)");
    g_x509_cred = cred;
    log_info("X.509 fallback credential registered (%zu certs) for non-DC clients", n);
}

/* ── Build (or rebuild, on SIGHUP) the server context from the sealed dir ── */
static SSL_CTX *build_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new");
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION))
        die("set_min_proto_version");

    if (g_x509_cert && g_x509_key) {
        /* Vanilla-TLS baseline: plain X.509 termination on the same
         * BoringSSL fork-per-connection data path as the DC terminator. */
        if (!SSL_CTX_use_certificate_chain_file(ctx, g_x509_cert))
            die("use_certificate_chain_file");
        if (!SSL_CTX_use_PrivateKey_file(ctx, g_x509_key, SSL_FILETYPE_PEM))
            die("use_PrivateKey_file");
        if (!SSL_CTX_check_private_key(ctx))
            die("check_private_key");
        log_info("Plain X.509 mode (vanilla baseline): cert=%s", g_x509_cert);
        return ctx;
    }

    char chain_path[512], dc_path[512], key_path[512], cert_path[512];
    snprintf(chain_path, sizeof(chain_path), "%s/frontend_chain.pem", g_sealed_dir);
    snprintf(dc_path,    sizeof(dc_path),    "%s/delegated_credential.bin", g_sealed_dir);
    snprintf(key_path,   sizeof(key_path),   "%s/private_key.pem", g_sealed_dir);
    snprintf(cert_path,  sizeof(cert_path),  "%s/certificate.pem", g_sealed_dir);
    log_info("Sealed dir: %s", g_sealed_dir);

    CRYPTO_BUFFER **fe_chain = NULL;
    size_t fe_chain_len = load_cert_chain_pem(chain_path, &fe_chain);
    log_info("Loaded frontend cert chain (%zu certs)", fe_chain_len);

    EVP_PKEY *backend_key = load_pkey(key_path);
    log_info("Loaded backend private key");

    size_t dc_len = 0;
    uint8_t *dc_bytes = read_file(dc_path, &dc_len);
    log_info("Loaded Delegated Credential (%zu bytes)", dc_len);

    /* DC credential: frontend cert chain + DC + backend key, for clients that
     * advertise DC support (browsers, the NSS client). */
    add_dc_credential(ctx, fe_chain, fe_chain_len, dc_bytes, dc_len, backend_key);

    /* X.509 credential: the backend's self-signed certificate over the same
     * key, for clients without DC support — the frontend's proxy-mode hop,
     * which pins this certificate's fingerprint (design §4.4).  BoringSSL
     * picks the DC credential when the client offers DCs and this one
     * otherwise. */
    if (access(cert_path, R_OK) == 0)
        add_x509_credential(ctx, cert_path, backend_key);
    else
        log_info("No %s — non-DC clients will be rejected", cert_path);
    return ctx;
}

static void on_sighup(int sig) { (void)sig; g_reload = 1; }

/* ── Connect to local backend app ────────────────────────────────────────── */
static int connect_backend(const char *host, int port)
{
    /* AF_UNIX path: --backend starts with '/'.  Skips the IP/TCP stack —
     * meaningful per-request savings vs 127.0.0.1 loopback when the proxy
     * and Flask share a host (the Janus production layout). */
    if (host[0] == '/') {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        if (strlen(host) >= sizeof(addr.sun_path)) { close(fd); return -1; }
        strncpy(addr.sun_path, host, sizeof(addr.sun_path) - 1);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
        return fd;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ── Bidirectional relay: SSL ↔ plain TCP socket ─────────────────────────── */

static void relay(SSL *ssl, int app_fd)
{
    int ssl_fd = SSL_get_fd(ssl);
    char buf[16384];

    fd_set rfds;
    while (1) {
        FD_ZERO(&rfds);
        FD_SET(ssl_fd, &rfds);
        FD_SET(app_fd, &rfds);
        int maxfd = ssl_fd > app_fd ? ssl_fd : app_fd;

        /* If SSL has buffered decrypted data, handle it without blocking */
        if (SSL_pending(ssl) > 0) {
            int n = SSL_read(ssl, buf, sizeof(buf));
            if (n > 0) { if (send(app_fd, buf, n, 0) <= 0) return; }
            else return;
            continue;
        }

        struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };
        int ready = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready <= 0) return;

        if (FD_ISSET(ssl_fd, &rfds)) {
            int n = SSL_read(ssl, buf, sizeof(buf));
            if (n <= 0) return;
            if (send(app_fd, buf, n, 0) <= 0) return;
        }

        if (FD_ISSET(app_fd, &rfds)) {
            ssize_t n = recv(app_fd, buf, sizeof(buf), 0);
            if (n <= 0) return;
            if (SSL_write(ssl, buf, (int)n) <= 0) return;
        }
    }
}

/* ── Per-connection handler ──────────────────────────────────────────────── */

/* PAPER: §5 Backend — DC-TLS terminates inside the TEE; plaintext is relayed only to the co-located application. */
static void handle(SSL *ssl)
{
    if (SSL_accept(ssl) != 1) {
        log_info("SSL_accept failed");
        ERR_print_errors_fp(stderr);
        return;
    }

    const SSL_CREDENTIAL *sel = SSL_get0_selected_credential(ssl);
    if (sel == g_dc_cred) {
        log_info("connection: DC credential used");
    } else {
        log_info("connection: internal credential used (BoringSSL may pick "
                 "DC credential internally — functionally equivalent)");
    }

    int app_fd = connect_backend(g_backend_host, g_backend_port);
    if (app_fd < 0) {
        log_info("Failed to connect to backend %s:%d", g_backend_host, g_backend_port);
        const char *err =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Length: 23\r\n\r\n"
            "Backend app unreachable";
        SSL_write(ssl, err, (int)strlen(err));
        SSL_shutdown(ssl);
        return;
    }

    relay(ssl, app_fd);
    close(app_fd);
    SSL_shutdown(ssl);
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

static void parse_args(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            g_listen_port = argv[++i];
        } else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            static char host_buf[256];
            strncpy(host_buf, argv[++i], sizeof(host_buf) - 1);
            char *colon = strchr(host_buf, ':');
            if (colon) {
                *colon = '\0';
                g_backend_host = host_buf;
                g_backend_port = atoi(colon + 1);
            } else {
                g_backend_host = host_buf;
            }
        } else if (strcmp(argv[i], "--sealed-dir") == 0 && i + 1 < argc) {
            g_sealed_dir = argv[++i];
        } else if (strcmp(argv[i], "--x509-cert") == 0 && i + 1 < argc) {
            g_x509_cert = argv[++i];
        } else if (strcmp(argv[i], "--x509-key") == 0 && i + 1 < argc) {
            g_x509_key = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--listen PORT] [--backend HOST:PORT] "
                   "[--sealed-dir DIR] [--x509-cert PEM --x509-key PEM]\n",
                   argv[0]);
            exit(0);
        }
    }
}

int main(int argc, char *argv[])
{
    parse_args(argc, argv);

    log_info("Listening on :%s, relaying to %s:%d", g_listen_port, g_backend_host, g_backend_port);

    /* Build SSL context (rebuilt on SIGHUP after a DC renewal, see build_ctx) */
    g_ctx = build_ctx();

    /* Listen */
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)atoi(g_listen_port)),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(srv_fd, 128) < 0) die("listen");
    log_info("Ready — accepting TLS+DC connections");

    /* Pidfile, one per instance (several terminators may share the sealed
     * dir), so the backend can SIGHUP every instance after it installs a
     * renewed DC or re-registers with a fresh key. */
    {
        char pid_path[512];
        snprintf(pid_path, sizeof(pid_path), "%s/dc_proxy.%s.pid", g_sealed_dir, g_listen_port);
        FILE *pf = fopen(pid_path, "w");
        if (pf) { fprintf(pf, "%d\n", (int)getpid()); fclose(pf); }
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    {
        /* No SA_RESTART: accept() must return EINTR so the reload runs
         * promptly rather than after the next connection. */
        struct sigaction sa = {0};
        sa.sa_handler = on_sighup;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGHUP, &sa, NULL);
    }

    while (1) {
        if (g_reload) {
            g_reload = 0;
            log_info("SIGHUP: reloading credentials from %s", g_sealed_dir);
            SSL_CTX *fresh = build_ctx();
            SSL_CTX *old = g_ctx;
            g_ctx = fresh;
            if (old) SSL_CTX_free(old);   /* forked children hold their own copy */
        }
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int cli_fd = accept(srv_fd, (struct sockaddr *)&cli, &cli_len);
        if (cli_fd < 0) {
            if (errno == EINTR) continue;   /* signal — loop re-checks g_reload */
            perror("accept");
            continue;
        }

        /* Disable Nagle and delayed-ACK on the client-facing socket.
         * Without these, small TLS responses (HTTP body + headers under one
         * MSS) get held by Linux's delayed-ACK timer for ~40 ms per request
         * before the kernel's piggyback-ACK heuristic gives up.  Diagnosed
         * via tcpdump: 41 ms gap between client's GET and server's response.
         * TCP_QUICKACK is sticky-off; re-set per ACK in higher-rate paths
         * if needed, but for the relay's request/response shape one-shot
         * suffices since each connection is short-lived. */
        int one = 1;
        setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY,  &one, sizeof(one));
        setsockopt(cli_fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        log_info("connection from %s:%d", ip, ntohs(cli.sin_port));

        pid_t pid = fork();
        if (pid == 0) {
            close(srv_fd);
            SSL *ssl = SSL_new(g_ctx);
            SSL_set_fd(ssl, cli_fd);
            handle(ssl);
            SSL_free(ssl);
            close(cli_fd);
            exit(0);
        }
        close(cli_fd);
    }

    return 0;
}
