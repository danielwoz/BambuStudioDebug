// pin_bypass.c — LD_PRELOAD interposer that forces libBambuSource.so's
// statically-linked OpenSSL to accept any server certificate, with zero memory
// patching, no ptrace, and no modification of the plugin binary.
//
// How it works
// ------------
// libBambuSource.so statically links OpenSSL 3.1.x + libcurl but exports every
// OpenSSL symbol under a `tutk_third_` prefix as a GLOBAL DEFAULT dynamic
// symbol, and calls them internally through its own PLT (each has an
// R_X86_64_JUMP_SLOT relocation; the library sets no DF_SYMBOLIC deep-binding
// flag). A symbol of the same name provided via LD_PRELOAD therefore sits
// earlier in the global scope and interposes the library's own internal calls —
// even calls the library makes to functions it also defines. This is verified:
// under LD_DEBUG=bindings the GOT slots for both symbols below bind to this
// object, not to BambuSource's own definitions.
//
// `ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk)` is the single gate: in
// OpenSSL 3.x the custom pinning callback installed via
// SSL_CTX_set_cert_verify_callback is dispatched *inside* this function, so
// replacing the whole function forces acceptance regardless of whether the pin
// is a standard X509_STORE check or an app verify callback. It returns >0 on
// success. SSL_get_verify_result is also pinned to X509_V_OK for any
// post-handshake check.
//
// Scope: the `tutk_third_` prefix is unique to BambuSource, so this touches only
// BambuSource's OpenSSL — Studio's own TLS (unprefixed symbols) and the GnuTLS
// login webview are unaffected.
//
// SCOPE LIMIT (important): this shim defeats certificate verification only for
// TLS that runs through *BambuSource's* OpenSSL (e.g. its libcurl legs / TUTK
// P2P). It does NOT defeat the cloud MQTT device-session pin. That connection is
// established by libbambu_networking.so using its OWN bundled, VMProtect-packed
// OpenSSL (internal symbols, no dynamic GOT), proven by an execution backtrace
// on the outbound connect() and by this shim's verify hook never being invoked
// during the MQTT handshake. See conn_origin_trace.c and docs/MITM_LOGGING.md.

#define X509_V_OK 0L

// int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk);  returns >0 == verified.
int tutk_third_ssl_verify_cert_chain(void *s, void *sk)
{
    (void)s;
    (void)sk;
    return 1;
}

// long SSL_get_verify_result(const SSL *ssl);
long tutk_third_SSL_get_verify_result(const void *ssl)
{
    (void)ssl;
    return X509_V_OK;
}
