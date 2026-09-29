/*
 * © 2026 Nokia
 * Licensed under the BSD 3-Clause Clear License
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/*
 * nss_dc_helper.c — persistent NSS-based Delegated-Credential TLS client.
 *
 * Purpose
 * -------
 * Janus redirect mode requires a client that genuinely performs the RFC 9345
 * client-side DC validation: receive the DC in the server's Certificate
 * message, verify it against the delegating (frontend) certificate, and use
 * the DC public key to verify CertificateVerify.  BoringSSL cannot do this
 * (server-side only); NSS — the stack Firefox uses — does it in-band.
 *
 * This helper isolates exactly that step (the paper's client pipeline step
 * (v) plus the chain validation step (i)) for the backend data connection.
 * It is driven by the Python bench, which performs the attestation checks
 * (ii)-(iv) on the control connection to the frontend.  Keeping the helper
 * persistent (one process, NSS initialised once, many handshakes) avoids
 * per-attempt process-spawn overhead so the reported timings reflect the
 * TLS+DC cost, not the measurement script.
 *
 * Protocol (line-oriented, stdin -> stdout)
 * -----------------------------------------
 *   stdin  : "<host> <port> <path>\n"                 (GET) per request, or
 *            "POST <host> <port> <path> <json-body>\n" (POST, body on one line)
 *   stdout : "OK tcp_ms=<f> tls_ms=<f> http_ms=<f> ttft_ms=<f> dc=<0|1> "
 *            "status=<n> leaf_sha256=<hex>\n" or "ERR <message>\n"
 *            http_ms = time to first response byte; ttft_ms = time to first
 *            SSE "data:" token (for streaming /generate).
 *   "QUIT\n" exits.
 *
 * Chain validation (step i) is real: the helper loads an NSS DB whose trust
 * store contains the deployment CA, and installs the standard auth-cert hook.
 * A handshake against an untrusted chain fails.  DC validation (step v) is
 * real: NSS rejects a malformed/forged DC in-band, which we verify with a
 * negative (tampered-DC) test.  ``dc=1`` confirms the peer actually
 * authenticated with a delegated credential (SSLChannelInfo.peerDelegCred).
 *
 * Build:  see Makefile.nss
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <nspr.h>
#include <private/pprio.h>   /* PR_ImportTCPSocket */
#include <nss.h>
#include <pk11pub.h>
#include <ssl.h>
#include <sslproto.h>
#include <sslt.h>
#include <sslerr.h>
#include <secerr.h>
#include <cert.h>
#include <secitem.h>

#ifndef SSL_ENABLE_DELEGATED_CREDENTIALS
#define SSL_ENABLE_DELEGATED_CREDENTIALS 40
#endif

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* Accept the chain that NSS's own validation produced.  We do NOT override
 * errors here: returning the result of the default hook keeps step (i)
 * (PKI path validation against the loaded trust store) genuinely enforced. */
static SECStatus auth_cert(void *arg, PRFileDesc *fd, PRBool checkSig,
                           PRBool isServer) {
    (void)arg;
    /* SSL_AuthCertificate validates the peer chain against the default
     * cert DB's trust store — the genuine step (i) PKI path validation.
     * It requires the cert DB handle as its first argument. */
    SECStatus rv = SSL_AuthCertificate(CERT_GetDefaultCertDB(), fd,
                                       checkSig, isServer);
    if (rv != SECSuccess && PR_GetError() == SSL_ERROR_BAD_CERT_DOMAIN) {
        /* Chain validation (trust) succeeded; only the DNS SAN mismatched
         * (testbed cert is issued for "localhost", we dial by IP).  Janus
         * binds the frontend's identity through the attestation extension,
         * not the certificate's DNS name, so a name-only mismatch is not a
         * trust failure here.  An untrusted *chain* fails earlier with
         * SEC_ERROR_UNKNOWN_ISSUER and is still rejected — which is what the
         * tampered-DC / untrusted-CA negative tests rely on. */
        return SECSuccess;
    }
    return rv;
}

/* Connect a plain TCP socket; return the fd or -1. */
static int tcp_connect(const char *host, int port) {
    struct addrinfo hints, *res = NULL;
    char portstr[16];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void hexenc(const unsigned char *in, int n, char *out) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = h[in[i] >> 4]; out[2*i+1] = h[in[i] & 0xf]; }
    out[2*n] = '\0';
}

/* One DC handshake + request.  body==NULL -> GET, else POST that JSON body.
 * Writes a result line to stdout (adds ttft_ms = time to first SSE token). */
static void do_request(const char *host, int port, const char *path,
                       const char *body) {
    double t0 = now_ms();
    int tcpfd = tcp_connect(host, port);
    if (tcpfd < 0) { printf("ERR tcp_connect\n"); fflush(stdout); return; }
    double t_tcp = now_ms();

    PRFileDesc *tcp = PR_ImportTCPSocket(tcpfd);
    if (!tcp) { close(tcpfd); printf("ERR import_socket\n"); fflush(stdout); return; }

    PRFileDesc *ssl = SSL_ImportFD(NULL, tcp);
    if (!ssl) { PR_Close(tcp); printf("ERR import_fd\n"); fflush(stdout); return; }

    /* TLS 1.3 only + enable client-side delegated credentials (step v). */
    SSLVersionRange vr = { SSL_LIBRARY_VERSION_TLS_1_3, SSL_LIBRARY_VERSION_TLS_1_3 };
    SSL_VersionRangeSet(ssl, &vr);
    SSL_OptionSet(ssl, SSL_ENABLE_DELEGATED_CREDENTIALS, PR_TRUE);
    SSL_OptionSet(ssl, SSL_NO_CACHE, PR_TRUE);  /* fresh handshake every time */
    SSL_AuthCertificateHook(ssl, auth_cert, NULL);
    SSL_SetURL(ssl, host);

    if (SSL_ResetHandshake(ssl, PR_FALSE /* not server */) != SECSuccess) {
        PR_Close(ssl); printf("ERR reset_handshake\n"); fflush(stdout); return;
    }
    if (SSL_ForceHandshake(ssl) != SECSuccess) {
        PR_Close(ssl);
        printf("ERR handshake %d\n", PR_GetError());
        fflush(stdout);
        return;
    }
    double t_tls = now_ms();

    /* Did the peer actually authenticate with a delegated credential? */
    SSLChannelInfo ci;
    int dc = 0;
    if (SSL_GetChannelInfo(ssl, &ci, sizeof(ci)) == SECSuccess) {
        dc = ci.peerDelegCred ? 1 : 0;
    }

    /* Leaf cert fingerprint so the Python side can bind this connection's
     * delegating cert to the attested frontend cert from the control conn. */
    char fp[65] = "na";
    CERTCertificate *leaf = SSL_PeerCertificate(ssl);
    if (leaf) {
        unsigned char digest[32];
        if (PK11_HashBuf(SEC_OID_SHA256, digest, leaf->derCert.data,
                         leaf->derCert.len) == SECSuccess) {
            hexenc(digest, 32, fp);
        }
        CERT_DestroyCertificate(leaf);
    }

    /* Build request: GET, or POST with a JSON body. Time both the first
     * response byte (http_ms = TTFB, ~headers) and the first SSE token
     * (ttft_ms) by reading until a "data:" event arrives in the body. */
    static char req[1 << 16];
    int rn;
    if (body) {
        rn = snprintf(req, sizeof(req),
                      "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                      "Content-Type: application/json\r\nContent-Length: %zu\r\n"
                      "Accept: */*\r\n\r\n%s", path, host, strlen(body), body);
    } else {
        rn = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                      "Accept: */*\r\n\r\n", path, host);
    }
    int status = 0;
    double t_first = t_tls, t_token = t_tls;
    if (rn > 0 && rn < (int)sizeof(req) && PR_Write(ssl, req, rn) == rn) {
        char buf[4096];
        static char acc[1 << 15];
        int acclen = 0, seen_first = 0, seen_token = 0;
        while (1) {
            int got = PR_Read(ssl, buf, sizeof(buf) - 1);
            if (got <= 0) break;
            double tnow = now_ms();
            buf[got] = '\0';
            if (!seen_first) {
                t_first = tnow; seen_first = 1;
                if (got >= 12 && strncmp(buf, "HTTP/1.", 7) == 0)
                    status = atoi(buf + 9);
            }
            if (acclen < (int)sizeof(acc) - 1) {
                int cp = got;
                if (cp > (int)sizeof(acc) - 1 - acclen) cp = sizeof(acc) - 1 - acclen;
                memcpy(acc + acclen, buf, cp); acclen += cp; acc[acclen] = '\0';
            }
            if (!seen_token && strstr(acc, "data:")) {
                t_token = tnow; seen_token = 1; break;
            }
        }
        if (!seen_token) t_token = t_first;  /* non-streaming reply */
    }

    PR_Close(ssl);
    printf("OK tcp_ms=%.4f tls_ms=%.4f http_ms=%.4f ttft_ms=%.4f dc=%d status=%d leaf_sha256=%s\n",
           t_tcp - t0, t_tls - t_tcp, t_first - t_tls, t_token - t_tls, dc, status, fp);
    fflush(stdout);
}

int main(int argc, char **argv) {
    const char *dbdir = (argc > 1) ? argv[1] : ".";

    /* NSS_Init initialises NSPR as needed; no explicit PR_Init required. */
    /* Real trust store: NSS validates the chain against this DB (step i). */
    if (NSS_Init(dbdir) != SECSuccess) {
        fprintf(stderr, "NSS_Init(%s) failed: %d\n", dbdir, PR_GetError());
        return 2;
    }
    NSS_SetDomesticPolicy();
    SSL_OptionSetDefault(SSL_ENABLE_DELEGATED_CREDENTIALS, PR_TRUE);
    SSL_OptionSetDefault(SSL_V2_COMPATIBLE_HELLO, PR_FALSE);

    fprintf(stderr, "nss_dc_helper ready (db=%s)\n", dbdir);

    static char line[1 << 16];   /* large: POST bodies (prompts) live here */
    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strcmp(line, "QUIT") == 0) break;
        char host[256], path[512];
        int port;
        /* "POST <host> <port> <path> <json-body>" (one line) or
         * "<host> <port> <path>" (GET). */
        if (strncmp(line, "POST ", 5) == 0) {
            int consumed = 0;
            if (sscanf(line + 5, "%255s %d %511s %n", host, &port, path,
                       &consumed) >= 3 && consumed > 0) {
                do_request(host, port, path, line + 5 + consumed);
            } else {
                printf("ERR bad_command\n"); fflush(stdout);
            }
        } else if (sscanf(line, "%255s %d %511s", host, &port, path) == 3) {
            do_request(host, port, path, NULL);
        } else {
            printf("ERR bad_command\n");
            fflush(stdout);
        }
    }

    NSS_Shutdown();
    PR_Cleanup();
    return 0;
}
