from sys import ffi
from utils import StringSlice, StaticString, StringRef

var _rustls = ffi.DLHandle("/opt/homebrew/lib/librustls.dylib", ffi.RTLD.LAZY)


@value
struct Result:
    var value: UInt32
    alias ok = Self(7000)
    alias io = Self(7001)
    alias null_parameter = Self(7002)
    alias invalid_dns_name_error = Self(7003)
    alias panic = Self(7004)
    alias certificate_parse_error = Self(7005)
    alias private_key_parse_error = Self(7006)
    alias insufficient_size = Self(7007)
    alias not_found = Self(7008)
    alias invalid_parameter = Self(7009)
    alias unexpected_eof = Self(7010)
    alias plaintext_empty = Self(7011)
    alias acceptor_not_ready = Self(7012)
    alias already_used = Self(7013)
    alias certificate_revocation_list_parse_error = Self(7014)
    alias no_server_cert_verifier = Self(7015)
    alias no_default_crypto_provider = Self(7016)
    alias get_random_failed = Self(7017)
    alias no_certificates_presented = Self(7101)
    alias decrypt_error = Self(7102)
    alias failed_to_get_current_time = Self(7103)
    alias failed_to_get_random_bytes = Self(7113)
    alias handshake_not_complete = Self(7104)
    alias peer_sent_oversized_record = Self(7105)
    alias no_application_protocol = Self(7106)
    alias bad_max_fragment_size = Self(7114)
    alias unsupported_name_type = Self(7115)
    alias encrypt_error = Self(7116)
    alias cert_encoding_bad = Self(7121)
    alias cert_expired = Self(7122)
    alias cert_not_yet_valid = Self(7123)
    alias cert_revoked = Self(7124)
    alias cert_unhandled_critical_extension = Self(7125)
    alias cert_unknown_issuer = Self(7126)
    alias cert_bad_signature = Self(7127)
    alias cert_not_valid_for_name = Self(7128)
    alias cert_invalid_purpose = Self(7129)
    alias cert_application_verification_failure = Self(7130)
    alias cert_other_error = Self(7131)
    alias cert_unknown_revocation_status = Self(7154)
    alias message_handshake_payload_too_large = Self(7133)
    alias message_invalid_ccs = Self(7134)
    alias message_invalid_content_type = Self(7135)
    alias message_invalid_cert_status_type = Self(7136)
    alias message_invalid_cert_request = Self(7137)
    alias message_invalid_dh_params = Self(7138)
    alias message_invalid_empty_payload = Self(7139)
    alias message_invalid_key_update = Self(7140)
    alias message_invalid_server_name = Self(7141)
    alias message_too_large = Self(7142)
    alias message_too_short = Self(7143)
    alias message_missing_data = Self(7144)
    alias message_missing_key_exchange = Self(7145)
    alias message_no_signature_schemes = Self(7146)
    alias message_trailing_data = Self(7147)
    alias message_unexpected_message = Self(7148)
    alias message_unknown_protocol_version = Self(7149)
    alias message_unsupported_compression = Self(7150)
    alias message_unsupported_curve_type = Self(7151)
    alias message_unsupported_key_exchange_algorithm = Self(7152)
    alias message_invalid_other = Self(7153)
    alias peer_incompatible_error = Self(7107)
    alias peer_misbehaved_error = Self(7108)
    alias inappropriate_message = Self(7109)
    alias inappropriate_handshake_message = Self(7110)
    alias general = Self(7112)
    alias alert_close_notify = Self(7200)
    alias alert_unexpected_message = Self(7201)
    alias alert_bad_record_mac = Self(7202)
    alias alert_decryption_failed = Self(7203)
    alias alert_record_overflow = Self(7204)
    alias alert_decompression_failure = Self(7205)
    alias alert_handshake_failure = Self(7206)
    alias alert_no_certificate = Self(7207)
    alias alert_bad_certificate = Self(7208)
    alias alert_unsupported_certificate = Self(7209)
    alias alert_certificate_revoked = Self(7210)
    alias alert_certificate_expired = Self(7211)
    alias alert_certificate_unknown = Self(7212)
    alias alert_illegal_parameter = Self(7213)
    alias alert_unknown_ca = Self(7214)
    alias alert_access_denied = Self(7215)
    alias alert_decode_error = Self(7216)
    alias alert_decrypt_error = Self(7217)
    alias alert_export_restriction = Self(7218)
    alias alert_protocol_version = Self(7219)
    alias alert_insufficient_security = Self(7220)
    alias alert_internal_error = Self(7221)
    alias alert_inappropriate_fallback = Self(7222)
    alias alert_user_canceled = Self(7223)
    alias alert_no_renegotiation = Self(7224)
    alias alert_missing_extension = Self(7225)
    alias alert_unsupported_extension = Self(7226)
    alias alert_certificate_unobtainable = Self(7227)
    alias alert_unrecognised_name = Self(7228)
    alias alert_bad_certificate_status_response = Self(7229)
    alias alert_bad_certificate_hash_value = Self(7230)
    alias alert_unknown_psk_identity = Self(7231)
    alias alert_certificate_required = Self(7232)
    alias alert_no_application_protocol = Self(7233)
    alias alert_unknown = Self(7234)
    alias cert_revocation_list_bad_signature = Self(7400)
    alias cert_revocation_list_invalid_crl_number = Self(7401)
    alias cert_revocation_list_invalid_revoked_cert_serial_number = Self(7402)
    alias cert_revocation_list_issuer_invalid_for_crl = Self(7403)
    alias cert_revocation_list_other_error = Self(7404)
    alias cert_revocation_list_parse_error = Self(7405)
    alias cert_revocation_list_unsupported_crl_version = Self(7406)
    alias cert_revocation_list_unsupported_critical_extension = Self(7407)
    alias cert_revocation_list_unsupported_delta_crl = Self(7408)
    alias cert_revocation_list_unsupported_indirect_crl = Self(7409)
    alias cert_revocation_list_unsupported_revocation_reason = Self(7410)
    alias client_cert_verifier_builder_no_root_anchors = Self(7500)

    fn __eq__(self, rhs: Self) -> Bool:
        return self.value == rhs.value

    fn __ne__(self, rhs: Self) -> Bool:
        return self.value != rhs.value


@value
struct TlsVersion:
    """
    Definitions of known TLS protocol versions.
    """

    var value: UInt32

    alias unknown = Self(0)
    alias sslv2 = Self(512)
    alias sslv3 = Self(768)
    alias tlsv1_0 = Self(769)
    alias tlsv1_1 = Self(770)
    alias tlsv1_2 = Self(771)
    alias tlsv1_3 = Self(772)

    fn __eq__(self, rhs: Self) -> Bool:
        return self.value == rhs.value

    fn __ne__(self, rhs: Self) -> Bool:
        return self.value != rhs.value


struct Accepted:
    """
    A parsed ClientHello produced by a rustls_acceptor.

    It is used to check server name indication (SNI), ALPN protocols,
    signature schemes, and cipher suites. It can be combined with a
    `rustls_server_config` to build a `rustls_connection`.
    """

    pass


struct AcceptedAlert:
    """Represents a TLS alert resulting from accepting a client."""

    pass


struct Acceptor:
    """
    A buffer and parser for ClientHello bytes.

    This allows reading ClientHello before choosing a rustls_server_config.

    It's useful when the server config will be based on parameters in the
    ClientHello: server name indication (SNI), ALPN protocols, signature
    schemes, and cipher suites.

    In particular, if a server wants to do some potentially expensive work
    to load a certificate for a given hostname, rustls_acceptor allows doing
    that asynchronously, as opposed to rustls_server_config_builder_set_hello_callback(),
    which doesn't work well for asynchronous I/O.

    The general flow is:
     - rustls_acceptor_new()
     - Loop:
       - Read bytes from the network it with rustls_acceptor_read_tls().
       - If successful, parse those bytes with rustls_acceptor_accept().
       - If that returns RUSTLS_RESULT_ACCEPTOR_NOT_READY, continue.
       - Otherwise, break.
     - If rustls_acceptor_accept() returned RUSTLS_RESULT_OK:
       - Examine the resulting rustls_accepted.
       - Create or select a rustls_server_config.
       - Call rustls_accepted_into_connection().
     - Otherwise, there was a problem with the ClientHello data and the
       connection should be rejected.
    """

    pass


struct Certificate:
    """
    An X.509 certificate, as used in rustls.
    Corresponds to `CertificateDer` in the Rust pki-types API.
    <https://docs.rs/rustls-pki-types/latest/rustls_pki_types/struct.CertificateDer.html>
    """

    pass


struct CertifiedKey:
    """
    The complete chain of certificates to send during a TLS handshake,
    plus a private key that matches the end-entity (leaf) certificate.

    Corresponds to `CertifiedKey` in the Rust API.
    <https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html>
    """

    pass


struct ClientCertVerifier:
    """
    A built client certificate verifier that can be provided to a `rustls_server_config_builder`
    with `rustls_server_config_builder_set_client_verifier`.
    """

    pass


struct ClientConfig:
    """
    A client config that is done being constructed and is now read-only.

    Under the hood, this object corresponds to an `Arc<ClientConfig>`.
    <https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html>
    """

    pass


struct ClientConfigBuilder:
    """
    A client config being constructed.

    A builder can be modified by, e.g. `rustls_client_config_builder_load_roots_from_file`.
    Once you're done configuring settings, call `rustls_client_config_builder_build`
    to turn it into a *rustls_client_config.

    Alternatively, if an error occurs or, you don't wish to build a config,
    call `rustls_client_config_builder_free` to free the builder directly.

    This object is not safe for concurrent mutation. Under the hood,
    it corresponds to a `Box<ClientConfig>`.
    <https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html>
    """

    pass


struct Connection:
    pass


struct CryptoProvider:
    """
    A C representation of a Rustls [`CryptoProvider`].
    """

    pass


struct CryptoProviderBuilder:
    """
    A `rustls_crypto_provider` builder.
    """

    pass


struct IoVec:
    """
    An alias for `struct iovec` from uio.h (on Unix) or `WSABUF` on Windows.

    You should cast `const struct rustls_iovec *` to `const struct iovec *` on
    Unix, or `const *LPWSABUF` on Windows. See [`std::io::IoSlice`] for details
    on interoperability with platform specific vectored IO.
    """

    pass


struct RootCertStore:
    """
    A root certificate store.
    <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html>
    """

    pass


struct RootCertStoreBuilder:
    """
    A `rustls_root_cert_store` being constructed.

    A builder can be modified by adding trust anchor root certificates with
    `rustls_root_cert_store_builder_add_pem`. Once you're done adding root certificates,
    call `rustls_root_cert_store_builder_build` to turn it into a `rustls_root_cert_store`.
    This object is not safe for concurrent mutation.
    """

    pass


struct ServerCertVerifier:
    """
    A built server certificate verifier that can be provided to a `rustls_client_config_builder`
    with `rustls_client_config_builder_set_server_verifier`.
    """

    pass


struct ServerConfig:
    """
    A server config that is done being constructed and is now read-only.

    Under the hood, this object corresponds to an `Arc<ServerConfig>`.
    <https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html>
    """

    pass


struct ServerConfigBuilder:
    """
    A server config being constructed.

    A builder can be modified by,
    e.g. rustls_server_config_builder_load_native_roots. Once you're
    done configuring settings, call rustls_server_config_builder_build
    to turn it into a *const rustls_server_config.

    Alternatively, if an error occurs or, you don't wish to build a config,
    call `rustls_server_config_builder_free` to free the builder directly.

    This object is not safe for concurrent mutation.
    <https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html>
    """

    pass


struct SigningKey:
    """
    A signing key that can be used to construct a certified key.
    """

    pass


struct SliceSliceBytes:
    """
    A read-only view of a slice of Rust byte slices.

    This is used to pass data from rustls-ffi to callback functions provided
    by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
    provide access via a pointer to an opaque struct and an accessor method
    that acts on that struct to get entries of type `rustls_slice_bytes`.
    Internally, the pointee is a `&[&[u8]]`.

    The memory exposed is available as specified by the function
    using this in its signature. For instance, when this is a parameter to a
    callback, the lifetime will usually be the duration of the callback.
    Functions that receive one of these must not call its methods beyond the
    allowed lifetime.
    """

    pass


struct SliceStr:
    """
    A read-only view of a slice of multiple Rust `&str`'s (that is, multiple
    strings).

    Like `rustls_str`, this guarantees that each string contains
    UTF-8 and no NUL bytes. Strings are not NUL-terminated.

    This is used to pass data from rustls-ffi to callback functions provided
    by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
    can't provide a straightforward `data` and `len` structure. Instead, we
    provide access via a pointer to an opaque struct and accessor methods.
    Internally, the pointee is a `&[&str]`.

    The memory exposed is available as specified by the function
    using this in its signature. For instance, when this is a parameter to a
    callback, the lifetime will usually be the duration of the callback.
    Functions that receive one of these must not call its methods beyond the
    allowed lifetime.
    """

    pass


struct SupportedCiphersuite:
    """
    A cipher suite supported by rustls.
    """

    pass


struct WebPkiClientCertVerifierBuilder:
    """
    A client certificate verifier being constructed.

    A builder can be modified by, e.g. `rustls_web_pki_client_cert_verifier_builder_add_crl`.

    Once you're done configuring settings, call `rustls_web_pki_client_cert_verifier_builder_build`
    to turn it into a `rustls_client_cert_verifier`.

    This object is not safe for concurrent mutation.

    See <https://docs.rs/rustls/latest/rustls/server/struct.ClientCertVerifierBuilder.html>
    for more information.
    """

    pass


struct WebPkiServerCertVerifierBuilder:
    """
    A server certificate verifier being constructed.

    A builder can be modified by, e.g. `rustls_web_pki_server_cert_verifier_builder_add_crl`.

    Once you're done configuring settings, call `rustls_web_pki_server_cert_verifier_builder_build`
    to turn it into a `rustls_server_cert_verifier`. This object is not safe for concurrent mutation.

    See <https://docs.rs/rustls/latest/rustls/client/struct.ServerCertVerifierBuilder.html>
    for more information.
    """

    pass


alias IoResult = Int32
"""
A return value for a function that may return either success (0) or a
non-zero value representing an error.

The values should match socket error numbers for your operating system --
for example, the integers for `ETIMEDOUT`, `EAGAIN`, or similar.
"""

alias ReadCallback = fn (
    userdata: UnsafePointer[NoneType],
    buf: UnsafePointer[UInt8],
    n: Int,
    out_n: UnsafePointer[Int],
) -> IoResult
"""
A callback for `rustls_connection_read_tls`.

An implementation of this callback should attempt to read up to n bytes from the
network, storing them in `buf`. If any bytes were stored, the implementation should
set out_n to the number of bytes stored and return 0.

If there was an error, the implementation should return a nonzero rustls_io_result,
which will be passed through to the caller.

On POSIX systems, returning `errno` is convenient.

On other systems, any appropriate error code works.

It's best to make one read attempt to the network per call. Additional reads will
be triggered by subsequent calls to one of the `_read_tls` methods.

`userdata` is set to the value provided to `rustls_connection_set_userdata`.
In most cases that should be a struct that contains, at a minimum, a file descriptor.

The buf and out_n pointers are borrowed and should not be retained across calls.
"""


@value
struct SliceBytes:
    """
    A read-only view on a Rust byte slice.

    This is used to pass data from rustls-ffi to callback functions provided
    by the user of the API.
    `len` indicates the number of bytes than can be safely read.

    The memory exposed is available as specified by the function
    using this in its signature. For instance, when this is a parameter to a
    callback, the lifetime will usually be the duration of the callback.
    Functions that receive one of these must not dereference the data pointer
    beyond the allowed lifetime.
    """

    var data: UnsafePointer[UInt8]
    var len: Int


alias WriteCallback = fn (
    userdata: UnsafePointer[NoneType],
    buf: UnsafePointer[UInt8],
    n: Int,
    out_n: UnsafePointer[Int],
) -> IoResult
"""
A callback for `rustls_connection_write_tls` or `rustls_accepted_alert_write_tls`.

An implementation of this callback should attempt to write the `n` bytes in buf
to the network.

If any bytes were written, the implementation should set `out_n` to the number of
bytes stored and return 0.

If there was an error, the implementation should return a nonzero `rustls_io_result`,
which will be passed through to the caller.

On POSIX systems, returning `errno` is convenient.

On other systems, any appropriate error code works.

It's best to make one write attempt to the network per call. Additional writes will
be triggered by subsequent calls to rustls_connection_write_tls.

`userdata` is set to the value provided to `rustls_connection_set_userdata`. In most
cases that should be a struct that contains, at a minimum, a file descriptor.

The buf and out_n pointers are borrowed and should not be retained across calls.
"""

alias VerifyServerCertUserData = UnsafePointer[NoneType]
"""
User-provided input to a custom certificate verifier callback.

See `rustls_client_config_builder_dangerous_set_certificate_verifier()`.
"""


@value
struct VerifyServerCertParams:
    """
    Input to a custom certificate verifier callback.

    See `rustls_client_config_builder_dangerous_set_certificate_verifier()`.

    server_name can contain a hostname, an IPv4 address in textual form, or an
    IPv6 address in textual form.
    """

    var end_entity_cert_der: SliceBytes
    var intermediate_certs_der: UnsafePointer[SliceSliceBytes]
    var server_name: StringRef
    var ocsp_response: SliceBytes


alias VerifyServerCertCallback = fn (
    userdata: VerifyServerCertUserData,
    params: UnsafePointer[VerifyServerCertParams],
) -> UInt32

alias LogLevel = Int


@value
struct LogParams:
    var level: LogLevel
    var message: StringRef


alias LogCallback = fn (
    UnsafePointer[NoneType], UnsafePointer[LogParams]
) -> None

alias WriteVectoredCallback = fn (
    UnsafePointer[NoneType], UnsafePointer[IoVec], Int, UnsafePointer[Int]
) -> IoResult
"""
A callback for `rustls_connection_write_tls_vectored`.

An implementation of this callback should attempt to write the bytes in
the given `count` iovecs to the network.

If any bytes were written, the implementation should set out_n to the number of
bytes written and return 0.

If there was an error, the implementation should return a nonzero rustls_io_result,
which will be passed through to the caller.

On POSIX systems, returning `errno` is convenient.

On other systems, any appropriate error code works.

It's best to make one write attempt to the network per call. Additional write will
be triggered by subsequent calls to one of the `_write_tls` methods.

`userdata` is set to the value provided to `rustls_*_session_set_userdata`. In most
cases that should be a struct that contains, at a minimum, a file descriptor.

The iov and out_n pointers are borrowed and should not be retained across calls.
"""

alias ClientHelloUserdata = UnsafePointer[NoneType]
"""
Any context information the callback will receive when invoked.
"""


struct SliceU16:
    """
    A read-only view on a Rust slice of 16-bit integers in platform endianness.

    This is used to pass data from rustls-ffi to callback functions provided
    by the user of the API.
    `len` indicates the number of bytes than can be safely read.

    The memory exposed is available as specified by the function
    using this in its signature. For instance, when this is a parameter to a
    callback, the lifetime will usually be the duration of the callback.
    Functions that receive one of these must not dereference the data pointer
    beyond the allowed lifetime.
    """

    var data: UnsafePointer[UInt16]
    var len: Int


struct ClientHello:
    """
    The TLS Client Hello information provided to a ClientHelloCallback function.

    `server_name` is the value of the ServerNameIndication extension provided
    by the client. If the client did not send an SNI, the length of this
    `rustls_string` will be 0.

    `signature_schemes` carries the values supplied by the client or, if the
    client did not send this TLS extension, the default schemes in the rustls library. See:
    <https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.SignatureScheme.html>.

    `alpn` carries the list of ALPN protocol names that the client proposed to
    the server. Again, the length of this list will be 0 if none were supplied.

    All this data, when passed to a callback function, is only accessible during
    the call and may not be modified. Users of this API must copy any values that
    they want to access when the callback returned.

    EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
    the rustls library is re-evaluating their current approach to client hello handling.
    """

    var server_name: StringRef
    var signature_schemes: SliceU16
    var alpn: UnsafePointer[SliceSliceBytes]


alias ClientHelloCallback = fn (
    ClientHelloUserdata, UnsafePointer[ClientHello]
) -> UnsafePointer[CertifiedKey]
"""
Prototype of a callback that can be installed by the application at the
`rustls_server_config`.

This callback will be invoked by a `rustls_connection` once the TLS client
hello message has been received.

`userdata` will be set based on rustls_connection_set_userdata.

`hello` gives the value of the available client announcements, as interpreted
by rustls. See the definition of `rustls_client_hello` for details.

NOTE:
- the passed in `hello` and all its values are only available during the
  callback invocations.
- the passed callback function must be safe to call multiple times concurrently
  with the same userdata, unless there is only a single config and connection
  where it is installed.

EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
the rustls library is re-evaluating their current approach to client hello handling.
"""

alias SessionStoreUserdata = UnsafePointer[NoneType]
"""
Any context information the callback will receive when invoked.
"""

alias SessionStoreGetCallback = fn (
    SessionStoreUserdata,
    UnsafePointer[SliceBytes],
    Int32,
    UnsafePointer[UInt8],
    Int,
    UnsafePointer[Int],
) -> UInt32
"""
Prototype of a callback that can be installed by the application at the
`rustls_server_config` or `rustls_client_config`.

This callback will be invoked by a TLS session when looking up the data
for a TLS session id.

`userdata` will be supplied based on rustls_{client,server}_session_set_userdata.

The `buf` points to `count` consecutive bytes where the
callback is expected to copy the result to. The number of copied bytes
needs to be written to `out_n`. The callback should not read any
data from `buf`.

If the value to copy is larger than `count`, the callback should never
do a partial copy but instead remove the value from its store and
act as if it was never found.

The callback should return RUSTLS_RESULT_OK to indicate that a value was
retrieved and written in its entirety into `buf`, or RUSTLS_RESULT_NOT_FOUND
if no session was retrieved.

When `remove_after` is != 0, the returned data needs to be removed
from the store.

NOTE: the passed in `key` and `buf` are only available during the
callback invocation.
NOTE: callbacks used in several sessions via a common config
must be implemented thread-safe.
"""

alias SessionStorePutCallback = fn (
    SessionStoreUserdata, UnsafePointer[SliceBytes], UnsafePointer[SliceBytes]
) -> UInt32
"""
Prototype of a callback that can be installed by the application at the
`rustls_server_config` or `rustls_client_config`.

This callback will be invoked by a TLS session when a TLS session
been created and an id for later use is handed to the client/has
been received from the server.

`userdata` will be supplied based on rustls_{client,server}_session_set_userdata.

The callback should return RUSTLS_RESULT_OK to indicate that a value was
successfully stored, or RUSTLS_RESULT_IO on failure.

NOTE: the passed in `key` and `val` are only available during the
callback invocation.
NOTE: callbacks used in several sessions via a common config
must be implemented thread-safe.
"""

var ALL_VERSIONS = _rustls.get_symbol[UInt16]("RUSTLS_ALL_VERSIONS")
"""
Rustls' list of supported protocol versions. The length of the array is
given by `RUSTLS_ALL_VERSIONS_LEN`.
"""

var ALL_VERSIONS_LEN = _rustls.get_symbol[Int]("RUSTLS_ALL_VERSIONS_LEN")[]
"""
The length of the array `RUSTLS_ALL_VERSIONS`.
"""


var DEFAULT_VERSIONS = _rustls.get_symbol[UInt16]("RUSTLS_DEFAULT_VERSIONS")
"""
Rustls' default list of protocol versions. The length of the array is
given by `RUSTLS_DEFAULT_VERSIONS_LEN`.
"""
var DEFAULT_VERSIONS_LEN = _rustls.get_symbol[Int](
    "RUSTLS_DEFAULT_VERSIONS_LEN"
)[]
"""
The length of the array `RUSTLS_DEFAULT_VERSIONS`.
"""


fn version() -> StaticString:
    """
    Returns a static string containing the rustls-ffi version as well as the
    rustls version. The string is alive for the lifetime of the program and does
    not need to be freed.
    """
    return StaticString(
        unsafe_from_utf8_strref=_rustls.get_function[fn () -> StringRef](
            "rustls_version"
        )()
    )


fn acceptor_new() -> UnsafePointer[Acceptor]:
    """
    Create and return a new rustls_acceptor.

    Caller owns the pointed-to memory and must eventually free it with
    `rustls_acceptor_free()`.
    """
    return _rustls.get_function[fn () -> UnsafePointer[Acceptor]](
        "rustls_acceptor_new"
    )()


fn acceptor_free(acceptor: UnsafePointer[Acceptor]):
    """
    Free a rustls_acceptor.

    Arguments:

    acceptor: The rustls_acceptor to free.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[Acceptor]) -> None](
        "rustls_acceptor_free"
    )(acceptor)


fn acceptor_read_tls(
    acceptor: UnsafePointer[Acceptor],
    callback: ReadCallback,
    userdata: UnsafePointer[NoneType],
    out_n: UnsafePointer[Int],
) -> IoResult:
    """
    Read some TLS bytes from the network into internal buffers.

    The actual network I/O is performed by `callback`, which you provide.
    Rustls will invoke your callback with a suitable buffer to store the
    read bytes into. You don't have to fill it up, just fill with as many
    bytes as you get in one syscall.

    Arguments:

    acceptor: The rustls_acceptor to read bytes into.
    callback: A function that will perform the actual network I/O.
      Must be valid to call with the given userdata parameter until
      this function call returns.
    userdata: An opaque parameter to be passed directly to `callback`.
      Note: this is distinct from the `userdata` parameter set with
      `rustls_connection_set_userdata`.
    out_n: An output parameter. This will be passed through to `callback`,
      which should use it to store the number of bytes written.

    Returns:

    - 0: Success. You should call `rustls_acceptor_accept()` next.
    - Any non-zero value: error.

    This function passes through return values from `callback`. Typically
    `callback` should return an errno value. See `rustls_read_callback()` for
    more details.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Acceptor],
            ReadCallback,
            UnsafePointer[NoneType],
            UnsafePointer[Int],
        ) -> IoResult
    ]("rustls_acceptor_read_tls")(acceptor, callback, userdata, out_n)


fn acceptor_accept(
    acceptor: UnsafePointer[Acceptor],
    out_accepted: UnsafePointer[UnsafePointer[Accepted]],
    out_alert: UnsafePointer[UnsafePointer[AcceptedAlert]],
) -> Result:
    """
    Parse all TLS bytes read so far.

    If those bytes make up a ClientHello, create a rustls_accepted from them.

    Arguments:

    acceptor: The rustls_acceptor to access.
    out_accepted: An output parameter. The pointed-to pointer will be set
      to a new rustls_accepted only when the function returns
      RUSTLS_RESULT_OK. The memory is owned by the caller and must eventually
      be freed
    out_alert: An output parameter. The pointed-to pointer will be set
      to a new rustls_accepted_alert only when the function returns
      a non-OK result. The memory is owned by the caller and must eventually
      be freed with rustls_accepted_alert_free. The caller should call
      rustls_accepted_alert_write_tls to write the alert bytes to the TLS
      connection before freeing the rustls_accepted_alert.

    At most one of out_accepted or out_alert will be set.

    Returns:

    - RUSTLS_RESULT_OK: a ClientHello has successfully been parsed.
      A pointer to a newly allocated rustls_accepted has been written to
      *out_accepted.
    - RUSTLS_RESULT_ACCEPTOR_NOT_READY: a full ClientHello has not yet been read.
      Read more TLS bytes to continue.
    - Any other rustls_result: the TLS bytes read so far cannot be parsed
      as a ClientHello, and reading additional bytes won't help.

    Memory and lifetimes:

    After this method returns RUSTLS_RESULT_OK, `acceptor` is
    still allocated and valid. It needs to be freed regardless of success
    or failure of this function.

    Calling `rustls_acceptor_accept()` multiple times on the same
    `rustls_acceptor` is acceptable from a memory perspective but pointless
    from a protocol perspective.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Acceptor],
            UnsafePointer[UnsafePointer[Accepted]],
            UnsafePointer[UnsafePointer[AcceptedAlert]],
        ) -> UInt32
    ]("rustls_acceptor_accept")(acceptor, out_accepted, out_alert)


fn accepted_server_name(accepted: UnsafePointer[Accepted]) -> StringRef:
    """
    Get the server name indication (SNI) from the ClientHello.

    Arguments:

    accepted: The rustls_accepted to access.

    Returns:

    A rustls_str containing the SNI field.

    The returned value is valid until rustls_accepted_into_connection or
    rustls_accepted_free is called on the same `accepted`. It is not owned
    by the caller and does not need to be freed.

    This will be a zero-length rustls_str in these error cases:

     - The SNI contains a NUL byte.
     - The `accepted` parameter was NULL.
     - The `accepted` parameter was already transformed into a connection
         with rustls_accepted_into_connection.
    """
    return _rustls.get_function[fn (UnsafePointer[Accepted]) -> StringRef](
        "rustls_accepted_server_name"
    )(accepted)


fn accepted_signature_scheme(
    accepted: UnsafePointer[Accepted], i: Int
) -> UInt16:
    """
    Get the i'th in the list of signature schemes offered in the ClientHello.

    This is useful in selecting a server certificate when there are multiple
    available for the same server name, for instance when selecting
    between an RSA and an ECDSA certificate.

    Arguments:

    accepted: The rustls_accepted to access.
    i: Fetch the signature scheme at this offset.

    Returns:

    A TLS Signature Scheme from <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme>

    This will be 0 in these cases:
      - i is greater than the number of available cipher suites.
      - accepted is NULL.
      - rustls_accepted_into_connection has already been called with `accepted`.
    """
    return _rustls.get_function[fn (UnsafePointer[Accepted], Int) -> UInt16](
        "rustls_accepted_signature_scheme"
    )(accepted, i)


fn accepted_cipher_suite(accepted: UnsafePointer[Accepted], i: Int) -> UInt16:
    """
    Get the i'th in the list of cipher suites offered in the ClientHello.

    Arguments:

    accepted: The rustls_accepted to access.
    i: Fetch the cipher suite at this offset.

    Returns:

    A cipher suite value from <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4.>

    This will be 0 in these cases:
      - i is greater than the number of available cipher suites.
      - accepted is NULL.
      - rustls_accepted_into_connection has already been called with `accepted`.

    Note that 0 is technically a valid cipher suite "TLS_NULL_WITH_NULL_NULL",
    but this library will never support null ciphers.
    """
    return _rustls.get_function[fn (UnsafePointer[Accepted], Int) -> UInt16](
        "rustls_accepted_cipher_suite"
    )(accepted, i)


fn accepted_alpn(accepted: UnsafePointer[Accepted], i: Int) -> SliceBytes:
    """
    Get the i'th in the list of ALPN protocols requested in the ClientHello.

    accepted: The rustls_accepted to access.
    i: Fetch the ALPN value at this offset.

    Returns:

    A rustls_slice_bytes containing the i'th ALPN protocol. This may
    contain internal NUL bytes and is not guaranteed to contain valid
    UTF-8.

    This will be a zero-length rustls_slice bytes in these cases:
      - i is greater than the number of offered ALPN protocols.
      - The client did not offer the ALPN extension.
      - The `accepted` parameter was already transformed into a connection
         with rustls_accepted_into_connection.

    The returned value is valid until rustls_accepted_into_connection or
    rustls_accepted_free is called on the same `accepted`. It is not owned
    by the caller and does not need to be freed.

    If you are calling this from Rust, note that the `'static` lifetime
    in the return signature is fake and must not be relied upon.
    """
    return _rustls.get_function[
        fn (UnsafePointer[Accepted], Int) -> SliceBytes
    ]("")(accepted, i)


fn accepted_into_connection(
    accepted: UnsafePointer[Accepted],
    config: UnsafePointer[ServerConfig],
    out_conn: UnsafePointer[UnsafePointer[Connection]],
    out_alert: UnsafePointer[UnsafePointer[AcceptedAlert]],
) -> Result:
    """
    Turn a rustls_accepted into a rustls_connection, given the provided
    rustls_server_config.

    Arguments:

    accepted: The rustls_accepted to transform.
    config: The configuration with which to create this connection.
    out_conn: An output parameter. The pointed-to pointer will be set
      to a new rustls_connection only when the function returns
      RUSTLS_RESULT_OK.
    out_alert: An output parameter. The pointed-to pointer will be set
      to a new rustls_accepted_alert when, and only when, the function returns
      a non-OK result. The memory is owned by the caller and must eventually
      be freed with rustls_accepted_alert_free. The caller should call
      rustls_accepted_alert_write_tls to write the alert bytes to
      the TLS connection before freeing the rustls_accepted_alert.

    At most one of out_conn or out_alert will be set.

    Returns:

    - RUSTLS_RESULT_OK: The `accepted` parameter was successfully
      transformed into a rustls_connection, and *out_conn was written to.
    - RUSTLS_RESULT_ALREADY_USED: This function was called twice on the
      same rustls_connection.
    - RUSTLS_RESULT_NULL_PARAMETER: One of the input parameters was NULL.

    Memory and lifetimes:

    In both success and failure cases, this consumes the contents of
    `accepted` but does not free its allocated memory. In either case,
    call rustls_accepted_free to avoid a memory leak.

    Calling accessor methods on an `accepted` after consuming it will
    return zero or default values.

    The rustls_connection emitted by this function in the success case
    is owned by the caller and must eventually be freed.

    This function does not take ownership of `config`. It does increment
    `config`'s internal reference count, indicating that the
    rustls_connection may hold a reference to it until it is done.
    See the documentation for rustls_connection for details.
    """
    return _rustls.get_function[fn () -> Result](
        "rustls_accepted_into_connection"
    )()


fn accepted_free(accepted: UnsafePointer[Accepted]):
    """
    Free a rustls_accepted.

    Arguments:

    accepted: The rustls_accepted to free.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    pass


fn accepted_alert_write_tls(
    accepted_alert: UnsafePointer[AcceptedAlert],
    callback: WriteCallback,
    userdata: UnsafePointer[NoneType],
    out_n: UnsafePointer[Int],
) -> IoResult:
    """
    Write some TLS bytes (an alert) to the network.

    The actual network I/O is performed by `callback`, which you provide.
    Rustls will invoke your callback with a suitable buffer containing TLS
    bytes to send. You don't have to write them all, just as many as you can
    in one syscall.

    The `userdata` parameter is passed through directly to `callback`. Note that
    this is distinct from the `userdata` parameter set with
    `rustls_connection_set_userdata`.

    Returns 0 for success, or an errno value on error. Passes through return values
    from callback. See [`rustls_write_callback`] or [`AcceptedAlert`] for
    more details.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[AcceptedAlert],
            WriteCallback,
            UnsafePointer[NoneType],
            UnsafePointer[Int],
        ) -> IoResult
    ]("rustls_accepted_alert_write_tls")(
        accepted_alert, callback, userdata, out_n
    )


fn accepted_alert_free(accepted_alert: UnsafePointer[AcceptedAlert]):
    """
    Free a rustls_accepted_alert.

    Arguments:

    accepted_alert: The rustls_accepted_alert to free.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[AcceptedAlert]) -> None](
        "rustls_accepted_alert_free"
    )(accepted_alert)


fn certificate_get_der(
    cert: UnsafePointer[Certificate],
    out_der_data: UnsafePointer[UnsafePointer[UInt8]],
    out_der_len: UnsafePointer[Int],
) -> Result:
    """
    Get the DER data of the certificate itself.
    The data is owned by the certificate and has the same lifetime.
    """
    return _rustls.get_function[fn () -> Result]("rustls_certificate_get_der")()


fn supported_ciphersuite_get_suite(
    supported_ciphersuite: UnsafePointer[SupportedCiphersuite],
) -> UInt16:
    """
    Return a 16-bit unsigned integer corresponding to this cipher suite's assignment from
    <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>.

    The bytes from the assignment are interpreted in network order.
    """
    return _rustls.get_function[
        fn (UnsafePointer[SupportedCiphersuite]) -> UInt16
    ]("rustls_supported_ciphersuite_get_suite")(supported_ciphersuite)


fn supported_ciphersuite_get_name(
    supported_ciphersuite: UnsafePointer[SupportedCiphersuite],
) -> StaticString:
    """
    Returns the name of the ciphersuite as a `rustls_str`.

    If the provided ciphersuite is invalid, the `rustls_str` will contain the
    empty string. The lifetime of the `rustls_str` is the lifetime of the program,
    it does not need to be freed.
    """
    return StaticString(
        unsafe_from_utf8_strref=_rustls.get_function[
            fn (UnsafePointer[SupportedCiphersuite]) -> StringRef
        ]("rustls_supported_ciphersuite_get_name")(supported_ciphersuite)
    )


fn supported_ciphersuite_protocol_version(
    supported_ciphersuite: UnsafePointer[SupportedCiphersuite],
) -> TlsVersion:
    """
    Returns the `rustls_tls_version` of the ciphersuite.

    See also `RUSTLS_ALL_VERSIONS`.
    """
    return _rustls.get_function[
        fn (UnsafePointer[SupportedCiphersuite]) -> TlsVersion
    ]("rustls_supported_ciphersuite_protocol_version")(supported_ciphersuite)


fn certified_key_build(
    cert_chain: UnsafePointer[UInt8],
    cert_chain_len: Int,
    private_key: UnsafePointer[UInt8],
    private_key_len: Int,
    certified_key_out: UnsafePointer[UnsafePointer[CertifiedKey]],
) -> Result:
    """
    Build a `rustls_certified_key` from a certificate chain and a private key
    and the default process-wide crypto provider.

    `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    a series of PEM-encoded certificates, with the end-entity (leaf)
    certificate first.

    `private_key` must point to a buffer of `private_key_len` bytes, containing
    a PEM-encoded private key in either PKCS#1, PKCS#8 or SEC#1 format when
    using `aws-lc-rs` as the crypto provider. Supported formats may vary by
    provider.

    On success, this writes a pointer to the newly created
    `rustls_certified_key` in `certified_key_out`. That pointer must later
    be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
    internally, this is an atomically reference-counted pointer, so even after
    the original caller has called `rustls_certified_key_free`, other objects
    may retain a pointer to the object. The memory will be freed when all
    references are gone.

    This function does not take ownership of any of its input pointers. It
    parses the pointed-to data and makes a copy of the result. You may
    free the cert_chain and private_key pointers after calling it.

    Typically, you will build a `rustls_certified_key`, use it to create a
    `rustls_server_config` (which increments the reference count), and then
    immediately call `rustls_certified_key_free`. That leaves the
    `rustls_server_config` in possession of the sole reference, so the
    `rustls_certified_key`'s memory will automatically be released when
    the `rustls_server_config` is freed.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[UInt8],
            Int,
            UnsafePointer[UInt8],
            Int,
            UnsafePointer[UnsafePointer[CertifiedKey]],
        ) -> UInt32
    ]("rustls_certified_key_build")(
        cert_chain,
        cert_chain_len,
        private_key,
        private_key_len,
        certified_key_out,
    )


fn certified_key_build_with_signing_key(
    cert_chain: UnsafePointer[UInt8],
    cert_chain_len: Int,
    signing_key: UnsafePointer[SigningKey],
    certified_key: UnsafePointer[UnsafePointer[CertifiedKey]],
) -> Result:
    """
    Build a `rustls_certified_key` from a certificate chain and a
    `rustls_signing_key`.

    `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    a series of PEM-encoded certificates, with the end-entity (leaf)
    certificate first.

    `signing_key` must point to a `rustls_signing_key` loaded using a
    `rustls_crypto_provider` and `rustls_crypto_provider_load_key()`.

    On success, this writes a pointer to the newly created
    `rustls_certified_key` in `certified_key_out`. That pointer must later
    be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
    internally, this is an atomically reference-counted pointer, so even after
    the original caller has called `rustls_certified_key_free`, other objects
    may retain a pointer to the object. The memory will be freed when all
    references are gone.

    This function does not take ownership of any of its input pointers. It
    parses the pointed-to data and makes a copy of the result. You may
    free the cert_chain and private_key pointers after calling it.

    Typically, you will build a `rustls_certified_key`, use it to create a
    `rustls_server_config` (which increments the reference count), and then
    immediately call `rustls_certified_key_free`. That leaves the
    `rustls_server_config` in possession of the sole reference, so the
    `rustls_certified_key`'s memory will automatically be released when
    the `rustls_server_config` is freed.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[UInt8],
            Int,
            UnsafePointer[SigningKey],
            UnsafePointer[UnsafePointer[CertifiedKey]],
        ) -> UInt32
    ]("rustls_certified_key_build_with_signing_key")(
        cert_chain, cert_chain_len, signing_key, certified_key
    )


fn certified_key_get_certificate(
    certified_key: UnsafePointer[CertifiedKey], i: Int
) -> UnsafePointer[Certificate]:
    """
    Return the i-th rustls_certificate in the rustls_certified_key.

    0 gives the end-entity certificate. 1 and higher give certificates from the chain.

    Indexes higher than the last available certificate return NULL.

    The returned certificate is valid until the rustls_certified_key is freed.
    """
    return _rustls.get_function[
        fn (UnsafePointer[CertifiedKey], Int) -> UnsafePointer[Certificate]
    ]("rustls_certified_key_get_certificate")(certified_key, i)


fn certified_key_clone_with_ocsp(
    certified_key: UnsafePointer[CertifiedKey],
    ocsp_response: UnsafePointer[SliceBytes],
    cloned_key_out: UnsafePointer[UnsafePointer[CertifiedKey]],
) -> Result:
    """
    Create a copy of the rustls_certified_key with the given OCSP response data
    as DER encoded bytes.

    The OCSP response may be given as NULL to clear any possibly present OCSP
    data from the cloned key.

    The cloned key is independent from its original and needs to be freed
    by the application.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CertifiedKey],
            UnsafePointer[SliceBytes],
            UnsafePointer[UnsafePointer[CertifiedKey]],
        ) -> UInt32
    ]("rustls_certified_key_clone_with_ocsp")(
        certified_key, ocsp_response, cloned_key_out
    )


fn certified_key_free(key: UnsafePointer[CertifiedKey]):
    """
    "Free" a certified_key previously returned from `rustls_certified_key_build`.

    Since certified_key is actually an atomically reference-counted pointer,
    extant certified_key may still hold an internal reference to the Rust object.

    However, C code must consider this pointer unusable after "free"ing it.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    return _rustls.get_function[fn (UnsafePointer[CertifiedKey]) -> None](
        "rustls_certified_key_free"
    )(key)


fn root_cert_store_builder_new() -> UnsafePointer[RootCertStoreBuilder]:
    """
    Create a `rustls_root_cert_store_builder`.

    Caller owns the memory and may free it with `rustls_root_cert_store_free`, regardless of
    whether `rustls_root_cert_store_builder_build` was called.

    If you wish to abandon the builder without calling `rustls_root_cert_store_builder_build`,
    it must be freed with `rustls_root_cert_store_builder_free`.
    """
    return _rustls.get_function[fn () -> UnsafePointer[RootCertStoreBuilder]](
        "rustls_root_cert_store_builder_new"
    )()


fn root_cert_store_builder_add_pem(
    builder: UnsafePointer[RootCertStoreBuilder],
    pem: UnsafePointer[UInt8],
    pem_len: Int,
    strict: Bool,
) -> Result:
    """
    Add one or more certificates to the root cert store builder using PEM
    encoded data.

    When `strict` is true an error will return a `CertificateParseError`
    result. So will an attempt to parse data that has zero certificates.

    When `strict` is false, unparseable root certificates will be ignored.
    This may be useful on systems that have syntactically invalid root
    certificates.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[RootCertStoreBuilder], UnsafePointer[UInt8], Int, Bool
        ) -> UInt32
    ]("rustls_root_cert_store_builder_add_pem")(builder, pem, pem_len, strict)


fn root_cert_store_builder_load_roots_from_file(
    builder: UnsafePointer[RootCertStoreBuilder],
    filename: UnsafePointer[Int8],
    strict: Bool,
) -> Result:
    """
    Add one or more certificates to the root cert store builder using PEM
    encoded data read from the named file.

    When `strict` is true an error will return a `CertificateParseError`
    result. So will an attempt to parse data that has zero certificates.

    When `strict` is false, unparseable root certificates will be ignored.
    This may be useful on systems that have syntactically invalid root
    certificates.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[RootCertStoreBuilder],
            UnsafePointer[Int8],
            Bool,
        ) -> UInt32
    ]("rustls_root_cert_store_builder_load_roots_from_file")(
        builder, filename, strict
    )


fn root_cert_store_builder_build(
    builder: UnsafePointer[RootCertStoreBuilder],
    root_cert_store_out: UnsafePointer[UnsafePointer[RootCertStore]],
) -> Result:
    """
    Create a new `rustls_root_cert_store` from the builder.

    The builder is consumed and cannot be used again, but must still be freed.

    The root cert store can be used in several `rustls_web_pki_client_cert_verifier_builder_new`
    instances and must be freed by the application when no longer needed. See the documentation of
    `rustls_root_cert_store_free` for details about lifetime.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[RootCertStoreBuilder],
            UnsafePointer[UnsafePointer[RootCertStore]],
        ) -> UInt32
    ]("rustls_root_cert_store_builder_build")(builder, root_cert_store_out)


fn root_cert_store_builder_free(
    builder: UnsafePointer[RootCertStoreBuilder],
):
    """
    Free a `rustls_root_cert_store_builder` previously returned from
    `rustls_root_cert_store_builder_new`.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[RootCertStoreBuilder]) -> None](
        "rustls_root_cert_store_builder_free"
    )(builder)


fn root_cert_store_free(store: UnsafePointer[RootCertStore]):
    """
    Free a rustls_root_cert_store previously returned from rustls_root_cert_store_builder_build.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[RootCertStore]) -> None](
        "rustls_root_cert_store_free"
    )(store)


fn client_cert_verifier_free(
    verifier: UnsafePointer[ClientCertVerifier],
):
    """
    Free a `rustls_client_cert_verifier` previously returned from
    `rustls_client_cert_verifier_builder_build`. Calling with NULL is fine. Must not be
    called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[ClientCertVerifier]) -> None](
        "rustls_client_cert_verifier_free"
    )(verifier)


fn web_pki_client_cert_verifier_builder_new(
    store: UnsafePointer[RootCertStore],
) -> UnsafePointer[WebPkiClientCertVerifierBuilder]:
    """
    Create a `rustls_web_pki_client_cert_verifier_builder` using the process-wide default
    cryptography provider.

    Caller owns the memory and may eventually call `rustls_web_pki_client_cert_verifier_builder_free`
    to free it, whether or not `rustls_web_pki_client_cert_verifier_builder_build` was called.

    Without further modification the builder will produce a client certificate verifier that
    will require a client present a client certificate that chains to one of the trust anchors
    in the provided `rustls_root_cert_store`. The root cert store must not be empty.

    Revocation checking will not be performed unless
    `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
    lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
    for the entire certificate chain unless
    `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    revocation status for certificates considered for revocation status will be treated as
    an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
    used.

    Unauthenticated clients will not be permitted unless
    `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.

    This copies the contents of the `rustls_root_cert_store`. It does not take
    ownership of the pointed-to data.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[RootCertStore],
        ) -> UnsafePointer[WebPkiClientCertVerifierBuilder]
    ]("rustls_web_pki_client_cert_verifier_builder_new")(store)


fn web_pki_client_cert_verifier_builder_new_with_provider(
    provider: UnsafePointer[CryptoProvider], store: UnsafePointer[RootCertStore]
) -> UnsafePointer[WebPkiClientCertVerifierBuilder]:
    """
    Create a `rustls_web_pki_client_cert_verifier_builder` using the specified
    cryptography provider.

    Caller owns the memory and may eventually call
    `rustls_web_pki_client_cert_verifier_builder_free` to free it, whether or
    not `rustls_web_pki_client_cert_verifier_builder_build` was called.

    Without further modification the builder will produce a client certificate verifier that
    will require a client present a client certificate that chains to one of the trust anchors
    in the provided `rustls_root_cert_store`. The root cert store must not be empty.

    Revocation checking will not be performed unless
    `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
    lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
    for the entire certificate chain unless
    `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    revocation status for certificates considered for revocation status will be treated as
    an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
    used.

    Unauthenticated clients will not be permitted unless
    `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.

    This copies the contents of the `rustls_root_cert_store`. It does not take
    ownership of the pointed-to data.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider], UnsafePointer[RootCertStore]
        ) -> UnsafePointer[WebPkiClientCertVerifierBuilder]
    ]("rustls_web_pki_client_cert_verifier_builder_new_with_provider")(
        provider, store
    )


fn web_pki_client_cert_verifier_builder_add_crl(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
    crl_pem: UnsafePointer[UInt8],
    crl_pem_len: Int,
) -> Result:
    """
    Add one or more certificate revocation lists (CRLs) to the client certificate verifier
    builder by reading the CRL content from the provided buffer of PEM encoded content.

    By default revocation checking will be performed on the entire certificate chain. To only
    check the revocation status of the end entity certificate, use
    `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation`.

    This function returns an error if the provided buffer is not valid PEM encoded content.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[WebPkiClientCertVerifierBuilder],
            UnsafePointer[UInt8],
            Int,
        ) -> UInt32
    ]("rustls_web_pki_client_cert_verifier_builder_add_crl")(
        builder, crl_pem, crl_pem_len
    )


fn web_pki_client_cert_verifier_only_check_end_entity_revocation(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
) -> Result:
    """
    When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, only
    check the revocation status of end entity certificates, ignoring any intermediate certificates
    in the chain.
    """
    return _rustls.get_function[
        fn (UnsafePointer[WebPkiClientCertVerifierBuilder],) -> UInt32
    ]("rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation")(
        builder
    )


fn web_pki_client_cert_verifier_allow_unknown_revocation_status(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
) -> Result:
    """
    When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, and it
    isn't possible to determine the revocation status of a considered certificate, do not treat
    it as an error condition.

    Overrides the default behavior where unknown revocation status is considered an error.
    """
    return _rustls.get_function[fn () -> Result](
        "rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status"
    )()


fn web_pki_client_cert_verifier_builder_allow_unauthenticated(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
) -> Result:
    """
    Allow unauthenticated anonymous clients in addition to those that present a client
    certificate that chains to one of the verifier's configured trust anchors.
    """
    return _rustls.get_function[
        fn (UnsafePointer[WebPkiClientCertVerifierBuilder]) -> UInt32
    ]("rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated")(
        builder
    )


fn web_pki_client_cert_verifier_clear_root_hint_subjects(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
) -> Result:
    """
    Clear the list of trust anchor hint subjects.

    By default, the client cert verifier will use the subjects provided by the root cert
    store configured for client authentication. Calling this function will remove these
    hint subjects, indicating the client should make a free choice of which certificate
    to send.
    """
    return _rustls.get_function[
        fn (UnsafePointer[WebPkiClientCertVerifierBuilder],) -> UInt32
    ]("rustls_web_pki_client_cert_verifier_clear_root_hint_subjects")(builder)


fn web_pki_client_cert_verifier_add_root_hint_subjects(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
    store: UnsafePointer[RootCertStore],
) -> Result:
    """
    Add additional distinguished names to the list of trust anchor hint subjects.

    By default, the client cert verifier will use the subjects provided by the root cert
    store configured for client authentication. Calling this function will add to these
    existing hint subjects. Calling this function with an empty `store` will have no
    effect, use `rustls_web_pki_client_cert_verifier_clear_root_hint_subjects` to clear
    the subject hints.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[WebPkiClientCertVerifierBuilder],
            UnsafePointer[RootCertStore],
        ) -> UInt32
    ]("rustls_web_pki_client_cert_verifier_add_root_hint_subjects")(
        builder, store
    )


fn web_pki_client_cert_verifier_builder_build(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
    verifier_out: UnsafePointer[UnsafePointer[ClientCertVerifier]],
) -> Result:
    """
    Create a new client certificate verifier from the builder.

    The builder is consumed and cannot be used again, but must still be freed.

    The verifier can be used in several `rustls_server_config` instances and must be
    freed by the application when no longer needed. See the documentation of
    `rustls_web_pki_client_cert_verifier_builder_free` for details about lifetime.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[WebPkiClientCertVerifierBuilder],
            UnsafePointer[UnsafePointer[ClientCertVerifier]],
        ) -> UInt32
    ]("rustls_web_pki_client_cert_verifier_builder_build")(
        builder, verifier_out
    )


fn web_pki_client_cert_verifier_builder_free(
    builder: UnsafePointer[WebPkiClientCertVerifierBuilder],
):
    """
    Free a `rustls_client_cert_verifier_builder` previously returned from
    `rustls_client_cert_verifier_builder_new`.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[
        fn (UnsafePointer[WebPkiClientCertVerifierBuilder]) -> None
    ]("rustls_web_pki_client_cert_verifier_builder_free")(builder)


fn web_pki_server_cert_verifier_builder_new(
    store: UnsafePointer[RootCertStore],
) -> UnsafePointer[WebPkiServerCertVerifierBuilder]:
    """
    Create a `rustls_web_pki_server_cert_verifier_builder` using the process-wide default
    crypto provider. Caller owns the memory and may free it with

    Caller owns the memory and may free it with `rustls_web_pki_server_cert_verifier_builder_free`,
    regardless of whether `rustls_web_pki_server_cert_verifier_builder_build` was called.

    Without further modification the builder will produce a server certificate verifier that
    will require a server present a certificate that chains to one of the trust anchors
    in the provided `rustls_root_cert_store`. The root cert store must not be empty.

    Revocation checking will not be performed unless
    `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
    lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
    for the entire certificate chain unless
    `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    revocation status for certificates considered for revocation status will be treated as
    an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
    used.

    This copies the contents of the `rustls_root_cert_store`. It does not take
    ownership of the pointed-to data.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[RootCertStore],
        ) -> UnsafePointer[WebPkiServerCertVerifierBuilder]
    ]("rustls_web_pki_server_cert_verifier_builder_new")(store)


fn web_pki_server_cert_verifier_builder_new_with_provider(
    provider: UnsafePointer[CryptoProvider], store: UnsafePointer[RootCertStore]
) -> UnsafePointer[WebPkiServerCertVerifierBuilder]:
    """
    Create a `rustls_web_pki_server_cert_verifier_builder` using the specified
    crypto provider. Caller owns the memory and may free it with
    `rustls_web_pki_server_cert_verifier_builder_free`, regardless of whether
    `rustls_web_pki_server_cert_verifier_builder_build` was called.

    Without further modification the builder will produce a server certificate verifier that
    will require a server present a certificate that chains to one of the trust anchors
    in the provided `rustls_root_cert_store`. The root cert store must not be empty.

    Revocation checking will not be performed unless
    `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
    lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
    for the entire certificate chain unless
    `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    revocation status for certificates considered for revocation status will be treated as
    an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
    used.

    This copies the contents of the `rustls_root_cert_store`. It does not take
    ownership of the pointed-to data.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider], UnsafePointer[RootCertStore]
        ) -> UnsafePointer[WebPkiServerCertVerifierBuilder]
    ]("rustls_web_pki_server_cert_verifier_builder_new_with_provider")(
        provider, store
    )


fn web_pki_server_cert_verifier_builder_add_crl(
    builder: UnsafePointer[WebPkiServerCertVerifierBuilder],
    crl_pem: UnsafePointer[UInt8],
    crl_pem_len: Int,
) -> Result:
    """
    Add one or more certificate revocation lists (CRLs) to the server certificate verifier
    builder by reading the CRL content from the provided buffer of PEM encoded content.

    By default revocation checking will be performed on the entire certificate chain. To only
    check the revocation status of the end entity certificate, use
    `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation`.

    This function returns an error if the provided buffer is not valid PEM encoded content.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[WebPkiServerCertVerifierBuilder],
            UnsafePointer[UInt8],
            Int,
        ) -> UInt32
    ]("rustls_web_pki_server_cert_verifier_builder_add_crl")(
        builder, crl_pem, crl_pem_len
    )


fn web_pki_server_cert_verifier_only_check_end_entity_revocation(
    builder: UnsafePointer[WebPkiServerCertVerifierBuilder],
) -> Result:
    """
    When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, only
    check the revocation status of end entity certificates, ignoring any intermediate certificates
    in the chain.
    """
    return _rustls.get_function[
        fn (UnsafePointer[WebPkiServerCertVerifierBuilder]) -> UInt32
    ]("rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation")(
        builder
    )


fn web_pki_server_cert_verifier_allow_unknown_revocation_status(
    builder: UnsafePointer[WebPkiServerCertVerifierBuilder],
) -> Result:
    """
    When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, and it
    isn't possible to determine the revocation status of a considered certificate, do not treat
    it as an error condition.

    Overrides the default behavior where unknown revocation status is considered an error.
    """
    return _rustls.get_function[
        fn (UnsafePointer[WebPkiServerCertVerifierBuilder]) -> UInt32
    ]("rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status")(
        builder
    )


fn web_pki_server_cert_verifier_builder_build(
    builder: UnsafePointer[WebPkiServerCertVerifierBuilder],
    verifier_out: UnsafePointer[UnsafePointer[ServerCertVerifier]],
) -> Result:
    """
    Create a new server certificate verifier from the builder.

    The builder is consumed and cannot be used again, but must still be freed.

    The verifier can be used in several `rustls_client_config` instances and must be
    freed by the application when no longer needed. See the documentation of
    `rustls_web_pki_server_cert_verifier_builder_free` for details about lifetime.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[WebPkiServerCertVerifierBuilder],
            UnsafePointer[UnsafePointer[ServerCertVerifier]],
        ) -> UInt32
    ]("rustls_web_pki_server_cert_verifier_builder_build")(
        builder, verifier_out
    )


fn web_pki_server_cert_verifier_builder_free(
    builder: UnsafePointer[WebPkiServerCertVerifierBuilder],
):
    """
    Free a `rustls_server_cert_verifier_builder` previously returned from
    `rustls_server_cert_verifier_builder_new`.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[
        fn (UnsafePointer[WebPkiServerCertVerifierBuilder]) -> None
    ]("rustls_web_pki_server_cert_verifier_builder_free")(builder)


fn platform_server_cert_verifier(
    verifier_out: UnsafePointer[UnsafePointer[ServerCertVerifier]],
) -> Result:
    """
    Create a verifier that uses the default behavior for the current platform.

    This uses [`rustls-platform-verifier`][].

    The verifier can be used in several `rustls_client_config` instances and must be freed by
    the application using `rustls_server_cert_verifier_free` when no longer needed.

    [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
    """
    return _rustls.get_function[
        fn (UnsafePointer[UnsafePointer[ServerCertVerifier]],) -> UInt32
    ]("rustls_platform_server_cert_verifier")(verifier_out)


fn platform_server_cert_verifier_with_provider(
    provider: UnsafePointer[CryptoProvider],
) -> UnsafePointer[ServerCertVerifier]:
    """
    Create a verifier that uses the default behavior for the current platform.

    This uses [`rustls-platform-verifier`][] and the specified crypto provider.

    The verifier can be used in several `rustls_client_config` instances and must be freed by
    the application using `rustls_server_cert_verifier_free` when no longer needed.

    [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
    """
    return _rustls.get_function[
        fn (UnsafePointer[CryptoProvider]) -> UnsafePointer[ServerCertVerifier]
    ]("rustls_platform_server_cert_verifier_with_provider")(provider)


fn server_cert_verifier_free(
    verifier: UnsafePointer[ServerCertVerifier],
):
    """
    Free a `rustls_server_cert_verifier` previously returned from
    `rustls_server_cert_verifier_builder_build` or `rustls_platform_server_cert_verifier`.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[ServerCertVerifier]) -> None](
        "rustls_server_cert_verifier_free"
    )(verifier)


fn client_config_builder_new() -> UnsafePointer[ClientConfigBuilder]:
    """
    Create a rustls_client_config_builder using the process default crypto provider.

    Caller owns the memory and must eventually call `rustls_client_config_builder_build`,
    then free the resulting `rustls_client_config`.

    Alternatively, if an error occurs or, you don't wish to build a config,
    call `rustls_client_config_builder_free` to free the builder directly.

    This uses the process default provider's values for the cipher suites and key
    exchange groups, as well as safe defaults for protocol versions.

    This starts out with no trusted roots. Caller must add roots with
    rustls_client_config_builder_load_roots_from_file or provide a custom verifier.
    """
    return _rustls.get_function[fn () -> UnsafePointer[ClientConfigBuilder]](
        "rustls_client_config_builder_new"
    )()


fn client_config_builder_new_custom(
    provider: UnsafePointer[CryptoProvider],
    tls_versions: UnsafePointer[UInt16],
    tls_versions_len: Int,
    builder_out: UnsafePointer[UnsafePointer[ClientConfigBuilder]],
) -> Result:
    """
    Create a rustls_client_config_builder using the specified crypto provider.

    Caller owns the memory and must eventually call `rustls_client_config_builder_build`,
    then free the resulting `rustls_client_config`.

    Alternatively, if an error occurs or, you don't wish to build a config,
    call `rustls_client_config_builder_free` to free the builder directly.

    `tls_version` sets the TLS protocol versions to use when negotiating a TLS session.
    `tls_version` is the version of the protocol, as defined in rfc8446,
    ch. 4.2.1 and end of ch. 5.1. Some values are defined in
    `rustls_tls_version` for convenience, and the arrays
    RUSTLS_DEFAULT_VERSIONS or RUSTLS_ALL_VERSIONS can be used directly.

    `tls_versions` will only be used during the call and the application retains
    ownership. `tls_versions_len` is the number of consecutive `uint16_t`
    pointed to by `tls_versions`.

    Ciphersuites are configured separately via the crypto provider. See
    `rustls_crypto_provider_builder_set_cipher_suites` for more information.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider],
            UnsafePointer[UInt16],
            Int,
            UnsafePointer[UnsafePointer[ClientConfigBuilder]],
        ) -> UInt32
    ]("rustls_client_config_builder_new_custom")(
        provider, tls_versions, tls_versions_len, builder_out
    )


fn client_config_builder_dangerous_set_certificate_verifier(
    config_builder: UnsafePointer[ClientConfigBuilder],
    callback: VerifyServerCertCallback,
) -> Result:
    """
    Set a custom server certificate verifier using the builder crypto provider.
    Returns rustls_result::NoDefaultCryptoProvider if no process default crypto
    provider has been set, and the builder was not constructed with an explicit
    provider choice.

    The callback must not capture any of the pointers in its
    rustls_verify_server_cert_params.
    If `userdata` has been set with rustls_connection_set_userdata, it
    will be passed to the callback. Otherwise the userdata param passed to
    the callback will be NULL.

    The callback must be safe to call on any thread at any time, including
    multiple concurrent calls. So, for instance, if the callback mutates
    userdata (or other shared state), it must use synchronization primitives
    to make such mutation safe.

    The callback receives certificate chain information as raw bytes.
    Currently this library offers no functions to parse the certificates,
    so you'll need to bring your own certificate parsing library
    if you need to parse them.

    If the custom verifier accepts the certificate, it should return
    RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
    Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
    section.

    <https://docs.rs/rustls/latest/rustls/client/struct.DangerousClientConfig.html#method.set_certificate_verifier>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder],
            VerifyServerCertCallback,
        ) -> UInt32
    ]("rustls_client_config_builder_dangerous_set_certificate_verifier")(
        config_builder, callback
    )


fn client_config_builder_set_server_verifier(
    builder: UnsafePointer[ClientConfigBuilder],
    verifier: UnsafePointer[ServerCertVerifier],
):
    """
    Configure the server certificate verifier.

    This increases the reference count of `verifier` and does not take ownership.
    """
    _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder],
            UnsafePointer[ServerCertVerifier],
        ) -> None
    ]("rustls_client_config_builder_set_server_verifier")(builder, verifier)


fn client_config_builder_set_alpn_protocols(
    builder: UnsafePointer[ClientConfigBuilder],
    protocol: UnsafePointer[SliceBytes],
    len: Int,
) -> Result:
    """
    Set the ALPN protocol list to the given protocols.

    `protocols` must point to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
    elements.

    Each element of the buffer must be a rustls_slice_bytes whose
    data field points to a single ALPN protocol ID.

    Standard ALPN protocol IDs are defined at
    <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.

    This function makes a copy of the data in `protocols` and does not retain
    any pointers, so the caller can free the pointed-to memory after calling.

    <https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.alpn_protocols>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder],
            UnsafePointer[SliceBytes],
            Int,
        ) -> UInt32
    ]("rustls_client_config_builder_set_alpn_protocols")(builder, protocol, len)


fn client_config_builder_set_enable_sni(
    builder: UnsafePointer[ClientConfigBuilder], enable: Bool
):
    """
    Enable or disable SNI.
    <https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html#structfield.enable_sni>
    """
    _rustls.get_function[fn (UnsafePointer[ClientConfigBuilder], Bool) -> None](
        "rustls_client_config_builder_set_enable_sni"
    )(builder, enable)


fn client_config_builder_set_certified_key(
    builder: UnsafePointer[ClientConfigBuilder],
    certified_keys: UnsafePointer[UnsafePointer[CertifiedKey]],
    certified_keys_len: Int,
) -> Result:
    """
    Provide the configuration a list of certificates where the connection
    will select the first one that is compatible with the server's signature
    verification capabilities.

    Clients that want to support both ECDSA and RSA certificates will want the
    ECSDA to go first in the list.

    The built configuration will keep a reference to all certified keys
    provided. The client may `rustls_certified_key_free()` afterwards
    without the configuration losing them. The same certified key may also
    be used in multiple configs.

    EXPERIMENTAL: installing a client authentication callback will replace any
    configured certified keys and vice versa.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder],
            UnsafePointer[UnsafePointer[CertifiedKey]],
            Int,
        ) -> UInt32
    ]("rustls_client_config_builder_set_certified_key")(
        builder, certified_keys, certified_keys_len
    )


fn client_config_builder_build(
    builder: UnsafePointer[ClientConfigBuilder],
    config_out: UnsafePointer[UnsafePointer[ClientConfig]],
) -> Result:
    """
    Turn a *rustls_client_config_builder (mutable) into a const *rustls_client_config
    (read-only).
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder],
            UnsafePointer[UnsafePointer[ClientConfig]],
        ) -> UInt32
    ]("rustls_client_config_builder_build")(builder, config_out)


fn client_config_builder_free(
    builder: UnsafePointer[ClientConfigBuilder],
):
    """
    "Free" a client_config_builder without building it into a rustls_client_config.

    Normally builders are built into rustls_client_config via `rustls_client_config_builder_build`
    and may not be free'd or otherwise used afterwards.

    Use free only when the building of a config has to be aborted before a config
    was created.
    """
    _rustls.get_function[fn (UnsafePointer[ClientConfigBuilder]) -> None](
        "rustls_client_config_builder_free"
    )(builder)


fn client_config_free(config: UnsafePointer[ClientConfig]):
    """
    "Free" a `rustls_client_config` previously returned from
    `rustls_client_config_builder_build`.

    Since `rustls_client_config` is actually an atomically reference-counted pointer,
    extant client connections may still hold an internal reference to the Rust object.

    However, C code must consider this pointer unusable after "free"ing it.

    Calling with NULL is fine. Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[ClientConfig]) -> None](
        "rustls_client_config_free"
    )(config)


fn client_connection_new(
    config: UnsafePointer[ClientConfig],
    server_name: UnsafePointer[Int8],
    conn_out: UnsafePointer[UnsafePointer[Connection]],
) -> Result:
    """
    Create a new rustls_connection containing a client connection and return
    it in the output parameter `conn_out`.

    If this returns an error code, the memory pointed to by `conn_out` remains
    unchanged.

    If this returns a non-error, the memory pointed to by `conn_out`
    is modified to point at a valid `rustls_connection`.  The caller now owns
    the `rustls_connection` and must call `rustls_connection_free` when done with it.

    The server_name parameter can contain a hostname or an IP address in
    textual form (IPv4 or IPv6). This function will return an error if it
    cannot be parsed as one of those types.
    """
    return _rustls.get_function[fn () -> Result](
        "rustls_client_connection_new"
    )()


fn connection_set_userdata(
    conn: UnsafePointer[Connection], userdata: UnsafePointer[NoneType]
):
    """
    Set the userdata pointer associated with this connection. This will be passed
    to any callbacks invoked by the connection, if you've set up callbacks in the config.
    The pointed-to data must outlive the connection.
    """
    _rustls.get_function[
        fn (UnsafePointer[Connection], UnsafePointer[NoneType]) -> None
    ]("rustls_connection_set_userdata")(conn, userdata)


fn connection_set_log_callback(
    conn: UnsafePointer[Connection], cb: LogCallback
):
    """
    Set the logging callback for this connection. The log callback will be invoked
    with the userdata parameter previously set by rustls_connection_set_userdata, or
    NULL if no userdata was set.
    """
    _rustls.get_function[fn (UnsafePointer[Connection], LogCallback) -> None](
        "rustls_connection_set_log_callback"
    )(conn, cb)


fn connection_read_tls(
    conn: UnsafePointer[Connection],
    callback: ReadCallback,
    userdata: UnsafePointer[NoneType],
    out_n: UnsafePointer[Int],
) -> IoResult:
    """
    Read some TLS bytes from the network into internal buffers. The actual network
    I/O is performed by `callback`, which you provide. Rustls will invoke your
    callback with a suitable buffer to store the read bytes into. You don't have
    to fill it up, just fill with as many bytes as you get in one syscall.
    The `userdata` parameter is passed through directly to `callback`. Note that
    this is distinct from the `userdata` parameter set with
    `rustls_connection_set_userdata`.
    Returns 0 for success, or an errno value on error. Passes through return values
    from callback. See rustls_read_callback for more details.
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.read_tls>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Connection],
            ReadCallback,
            UnsafePointer[NoneType],
            UnsafePointer[Int],
        ) -> IoResult
    ]("rustls_connection_read_tls")(conn, callback, userdata, out_n)


fn connection_write_tls(
    conn: UnsafePointer[Connection],
    callback: WriteCallback,
    userdata: UnsafePointer[NoneType],
    out_n: UnsafePointer[Int],
) -> IoResult:
    """
    Write some TLS bytes to the network. The actual network I/O is performed by
    `callback`, which you provide. Rustls will invoke your callback with a
    suitable buffer containing TLS bytes to send. You don't have to write them
    all, just as many as you can in one syscall.
    The `userdata` parameter is passed through directly to `callback`. Note that
    this is distinct from the `userdata` parameter set with
    `rustls_connection_set_userdata`.
    Returns 0 for success, or an errno value on error. Passes through return values
    from callback. See rustls_write_callback for more details.
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.write_tls>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Connection],
            WriteCallback,
            UnsafePointer[NoneType],
            UnsafePointer[Int],
        ) -> IoResult
    ]("rustls_connection_write_tls")(conn, callback, userdata, out_n)


fn connection_write_tls_vectored(
    conn: UnsafePointer[Connection],
    callback: WriteVectoredCallback,
    userdata: UnsafePointer[NoneType],
    out_n: UnsafePointer[Int],
) -> IoResult:
    """
    Write all available TLS bytes to the network. The actual network I/O is performed by
    `callback`, which you provide. Rustls will invoke your callback with an array
    of rustls_slice_bytes, each containing a buffer with TLS bytes to send.
    You don't have to write them all, just as many as you are willing.
    The `userdata` parameter is passed through directly to `callback`. Note that
    this is distinct from the `userdata` parameter set with
    `rustls_connection_set_userdata`.
    Returns 0 for success, or an errno value on error. Passes through return values
    from callback. See rustls_write_callback for more details.
    <https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write_vectored>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Connection],
            WriteVectoredCallback,
            UnsafePointer[NoneType],
            UnsafePointer[Int],
        ) -> IoResult
    ]("rustls_connection_write_tls_vectored")(conn, callback, userdata, out_n)


fn connection_process_new_packets(conn: UnsafePointer[Connection]) -> Result:
    """
    Decrypt any available ciphertext from the internal buffer and put it
    into the internal plaintext buffer, potentially making bytes available
    for rustls_connection_read().
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.process_new_packets>
    """
    return _rustls.get_function[fn (UnsafePointer[Connection]) -> Result](
        "rustls_connection_process_new_packets"
    )(conn)


fn connection_wants_read(conn: UnsafePointer[Connection]) -> Bool:
    """<https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_read>
    """
    return _rustls.get_function[fn (UnsafePointer[Connection]) -> Bool](
        "rustls_connection_wants_read"
    )(conn)


fn connection_wants_write(conn: UnsafePointer[Connection]) -> Bool:
    """<https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_write>
    """
    return _rustls.get_function[fn (UnsafePointer[Connection]) -> Bool](
        "rustls_connection_wants_write"
    )(conn)


fn connection_is_handshaking(conn: UnsafePointer[Connection]) -> Bool:
    """
    Returns true if the connection is currently performing the TLS handshake.

    Note: This may return `false` while there are still handshake packets waiting
    to be extracted and transmitted with `rustls_connection_write_tls()`.

    See the rustls documentation for more information.

    <https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.is_handshaking>
    """
    return _rustls.get_function[fn (UnsafePointer[Connection]) -> Bool](
        "rustls_connection_is_handshaking"
    )(conn)


fn connection_set_buffer_limit(conn: UnsafePointer[Connection], n: Int):
    """
    Sets a limit on the internal buffers used to buffer unsent plaintext (prior
    to completing the TLS handshake) and unsent TLS records. By default, there
    is no limit. The limit can be set at any time, even if the current buffer
    use is higher.
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.set_buffer_limit>
    """
    _rustls.get_function[fn (UnsafePointer[Connection], Int) -> None](
        "rustls_connection_set_buffer_limit"
    )(conn, n)


fn connection_send_close_notify(conn: UnsafePointer[Connection]):
    """
    Queues a close_notify fatal alert to be sent in the next write_tls call.
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.send_close_notify>
    """
    _rustls.get_function[fn (UnsafePointer[Connection]) -> None](
        "rustls_connection_send_close_notify"
    )(conn)


fn connection_get_peer_certificate(
    conn: UnsafePointer[Connection], i: Int
) -> UnsafePointer[Certificate]:
    """
    Return the i-th certificate provided by the peer.
    Index 0 is the end entity certificate. Higher indexes are certificates
    in the chain. Requesting an index higher than what is available returns
    NULL.
    The returned pointer is valid until the next mutating function call
    affecting the connection. A mutating function call is one where the
    first argument has type `struct rustls_connection *` (as opposed to
     `const struct rustls_connection *`).
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.peer_certificates>
    """
    return _rustls.get_function[
        fn (UnsafePointer[Connection], Int) -> UnsafePointer[Certificate]
    ]("rustls_connection_get_peer_certificate")(conn, i)


fn connection_get_alpn_protocol(
    conn: UnsafePointer[Connection],
    protocol_out: UnsafePointer[UnsafePointer[UInt8]],
    protocol_out_len: UnsafePointer[Int],
):
    """
    Get the ALPN protocol that was negotiated, if any. Stores a pointer to a
    borrowed buffer of bytes, and that buffer's len, in the output parameters.
    The borrow lives as long as the connection.
    If the connection is still handshaking, or no ALPN protocol was negotiated,
    stores NULL and 0 in the output parameters.
    The provided pointer is valid until the next mutating function call
    affecting the connection. A mutating function call is one where the
    first argument has type `struct rustls_connection *` (as opposed to
     `const struct rustls_connection *`).
    <https://www.iana.org/assignments/tls-parameters/>
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.alpn_protocol>
    """
    _rustls.get_function[
        fn (
            UnsafePointer[Connection],
            UnsafePointer[UnsafePointer[UInt8]],
            UnsafePointer[Int],
        ) -> None
    ]("rustls_connection_get_alpn_protocol")(
        conn, protocol_out, protocol_out_len
    )


fn connection_get_protocol_version(
    conn: UnsafePointer[Connection],
) -> UInt16:
    """
    Return the TLS protocol version that has been negotiated. Before this
    has been decided during the handshake, this will return 0. Otherwise,
    the u16 version number as defined in the relevant RFC is returned.
    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.protocol_version>
    <https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.ProtocolVersion.html>
    """
    return _rustls.get_function[fn (UnsafePointer[Connection]) -> UInt16](
        "rustls_connection_get_protocol_version"
    )(conn)


fn connection_get_negotiated_ciphersuite(
    conn: UnsafePointer[Connection],
) -> UInt16:
    """
    Retrieves the [IANA registered cipher suite identifier][IANA] agreed with the peer.

    This returns `TLS_NULL_WITH_NULL_NULL` (0x0000) until the ciphersuite is agreed.

    [IANA]: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>
    """
    return _rustls.get_function[fn (UnsafePointer[Connection]) -> UInt16](
        "rustls_connection_get_negotiated_ciphersuite"
    )(conn)


fn connection_get_negotiated_ciphersuite_name(
    conn: UnsafePointer[Connection],
) -> StringRef:
    """
    Retrieves the cipher suite name agreed with the peer.

    This returns "" until the ciphersuite is agreed.

    The lifetime of the `rustls_str` is the lifetime of the program, it does not
    need to be freed.

    <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.negotiated_cipher_suite>
    """
    return _rustls.get_function[fn (UnsafePointer[Connection]) -> StringRef](
        "rustls_connection_get_negotiated_ciphersuite_name"
    )(conn)


fn connection_write(
    conn: UnsafePointer[Connection],
    buf: UnsafePointer[UInt8],
    count: Int,
    out_n: UnsafePointer[Int],
) -> Result:
    """
    Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
    This will increase the number of output bytes available to
    `rustls_connection_write_tls`.
    On success, store the number of bytes actually written in *out_n
    (this may be less than `count`).
    <https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Connection],
            UnsafePointer[UInt8],
            Int,
            UnsafePointer[Int],
        ) -> UInt32
    ]("rustls_connection_write")(conn, buf, count, out_n)


fn connection_read(
    conn: UnsafePointer[Connection],
    buf: UnsafePointer[UInt8],
    count: Int,
    out_n: UnsafePointer[Int],
) -> Result:
    """
    Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
    On success, store the number of bytes read in *out_n (this may be less
    than `count`). A success with *out_n set to 0 means "all bytes currently
    available have been read, but more bytes may become available after
    subsequent calls to rustls_connection_read_tls and
    rustls_connection_process_new_packets."

    Subtle note: Even though this function only writes to `buf` and does not
    read from it, the memory in `buf` must be initialized before the call (for
    Rust-internal reasons). Initializing a buffer once and then using it
    multiple times without zeroizing before each call is fine.
    <https://docs.rs/rustls/latest/rustls/struct.Reader.html#method.read>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Connection],
            UnsafePointer[UInt8],
            Int,
            UnsafePointer[Int],
        ) -> UInt32
    ]("rustls_connection_read")(conn, buf, count, out_n)


fn connection_free(conn: UnsafePointer[Connection]):
    """
    Free a rustls_connection. Calling with NULL is fine.
    Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[Connection]) -> None](
        "rustls_connection_free"
    )(conn)


fn crypto_provider_builder_new_from_default(
    builder_out: UnsafePointer[UnsafePointer[CryptoProviderBuilder]],
) -> Result:
    """
    Constructs a new `rustls_crypto_provider_builder` using the process-wide default crypto
    provider as the base crypto provider to be customized.

    When this function returns `rustls_result::Ok` a pointer to the `rustls_crypto_provider_builder`
    is written to `builder_out`. It returns `rustls_result::NoDefaultCryptoProvider` if no default
    provider has been registered.

    The caller owns the returned `rustls_crypto_provider_builder` and must free it using
    `rustls_crypto_provider_builder_free`.

    This function is typically used for customizing the default crypto provider for specific
    connections. For example, a typical workflow might be to:

    * Either:
      * Use the default `aws-lc-rs` or `*ring*` provider that rustls-ffi is built with based on
        the `CRYPTO_PROVIDER` build variable.
      * Call `rustls_crypto_provider_builder_new_with_base` with the desired provider, and
        then install it as the process default with
        `rustls_crypto_provider_builder_build_as_default`.
    * Afterward, as required for customization:
      * Use `rustls_crypto_provider_builder_new_from_default` to get a builder backed by the
        default crypto provider.
      * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
        ciphersuites.
      * Use `rustls_crypto_provider_builder_build` to build a customized provider.
      * Provide that customized provider to client or server configuration builders.
    """
    res = _rustls.get_function[
        fn (UnsafePointer[UnsafePointer[CryptoProviderBuilder]]) -> UInt32
    ]("rustls_crypto_provider_builder_new_from_default")(builder_out)
    return res


fn crypto_provider_builder_new_with_base(
    base: UnsafePointer[CryptoProvider],
) -> UnsafePointer[CryptoProviderBuilder]:
    """
    Constructs a new `rustls_crypto_provider_builder` using the given `rustls_crypto_provider`
    as the base crypto provider to be customized.

    The caller owns the returned `rustls_crypto_provider_builder` and must free it using
    `rustls_crypto_provider_builder_free`.

    This function can be used for setting the default process wide crypto provider,
    or for constructing a custom crypto provider for a specific connection. A typical
    workflow could be to:

    * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
    * Install the custom provider as the process-wide default with
      `rustls_crypto_provider_builder_build_as_default`.

    Or, for per-connection customization:

    * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
    * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
      ciphersuites.
    * Use `rustls_crypto_provider_builder_build` to build a customized provider.
    * Provide that customized provider to client or server configuration builders.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider],
        ) -> UnsafePointer[CryptoProviderBuilder]
    ]("rustls_crypto_provider_builder_new_with_base")(base)


fn crypto_provider_builder_set_cipher_suites(
    builder: UnsafePointer[CryptoProviderBuilder],
    cipher_suites: UnsafePointer[UnsafePointer[SupportedCiphersuite]],
    cipher_suites_len: Int,
) -> Result:
    """
    Customize the supported ciphersuites of the `rustls_crypto_provider_builder`.

    Returns an error if the builder has already been built. Overwrites any previously
    set ciphersuites.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProviderBuilder],
            UnsafePointer[UnsafePointer[SupportedCiphersuite]],
            Int,
        ) -> UInt32
    ]("rustls_crypto_provider_builder_set_cipher_suites")(
        builder, cipher_suites, cipher_suites_len
    )


fn crypto_provider_builder_build(
    builder: UnsafePointer[CryptoProviderBuilder],
    provider_out: UnsafePointer[UnsafePointer[CryptoProvider]],
) -> Result:
    """
    Builds a `rustls_crypto_provider` from the builder and returns it. Returns an error if the
    builder has already been built.

    The `rustls_crypto_provider_builder` builder is consumed and should not be used
    for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
    still free the builder after a successful build.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProviderBuilder],
            UnsafePointer[UnsafePointer[CryptoProvider]],
        ) -> UInt32
    ]("rustls_crypto_provider_builder_build")(builder, provider_out)


fn crypto_provider_builder_build_as_default(
    builder: UnsafePointer[CryptoProviderBuilder],
) -> Result:
    """
    Builds a `rustls_crypto_provider` from the builder and sets it as the
    process-wide default crypto provider.

    Afterward, the default provider can be retrieved using `rustls_crypto_provider_default`.

    This can only be done once per process, and will return an error if a
    default provider has already been set, or if the builder has already been built.

    The `rustls_crypto_provider_builder` builder is consumed and should not be used
    for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
    still free the builder after a successful build.
    """
    return _rustls.get_function[
        fn (UnsafePointer[CryptoProviderBuilder]) -> UInt32
    ]("rustls_crypto_provider_builder_build_as_default")(builder)


fn crypto_provider_builder_free(
    builder: UnsafePointer[CryptoProviderBuilder],
):
    """
    Free the `rustls_crypto_provider_builder`.

    Calling with `NULL` is fine.
    Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[CryptoProviderBuilder]) -> None](
        "rustls_crypto_provider_builder_free"
    )(builder)


fn ring_crypto_provider() -> UnsafePointer[CryptoProvider]:
    """
    Return the `rustls_crypto_provider` backed by the `*ring*` cryptography library.

    The caller owns the returned `rustls_crypto_provider` and must free it using
    `rustls_crypto_provider_free`.
    """
    return _rustls.get_function[fn () -> UnsafePointer[CryptoProvider]](
        "rustls_ring_crypto_provider"
    )()


fn aws_lc_rs_crypto_provider() -> UnsafePointer[CryptoProvider]:
    """
    Return the `rustls_crypto_provider` backed by the `aws-lc-rs` cryptography library.

    The caller owns the returned `rustls_crypto_provider` and must free it using
    `rustls_crypto_provider_free`.
    """
    return _rustls.get_function[fn () -> UnsafePointer[CryptoProvider]](
        "rustls_aws_lc_rs_crypto_provider"
    )()


fn crypto_provider_default() -> UnsafePointer[CryptoProvider]:
    """
    Retrieve a pointer to the process default `rustls_crypto_provider`.

    This may return `NULL` if no process default provider has been set using
    `rustls_crypto_provider_builder_build_default`.

    Caller owns the returned `rustls_crypto_provider` and must free it w/ `rustls_crypto_provider_free`.
    """
    return _rustls.get_function[fn () -> UnsafePointer[CryptoProvider]](
        "rustls_crypto_provider_default"
    )()


fn crypto_provider_ciphersuites_len(
    provider: UnsafePointer[CryptoProvider],
) -> Int:
    """
    Returns the number of ciphersuites the `rustls_crypto_provider` supports.

    You can use this to know the maximum allowed index for use with
    `rustls_crypto_provider_ciphersuites_get`.

    This function will return 0 if the `provider` is NULL.
    """
    return _rustls.get_function[fn (UnsafePointer[CryptoProvider]) -> Int](
        "rustls_crypto_provider_ciphersuites_len"
    )(provider)


fn crypto_provider_ciphersuites_get(
    provider: UnsafePointer[CryptoProvider], index: Int
) -> UnsafePointer[SupportedCiphersuite]:
    """
    Retrieve a pointer to a supported ciphersuite of the `rustls_crypto_provider`.

    This function will return NULL if the `provider` is NULL, or if the index is out of bounds
    with respect to `rustls_crypto_provider_ciphersuites_len`.

    The lifetime of the returned `rustls_supported_ciphersuite` is equal to the lifetime of the
    `provider` and should not be used after the `provider` is freed.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider], Int
        ) -> UnsafePointer[SupportedCiphersuite]
    ]("rustls_supported_ciphersuite")(provider, index)


fn crypto_provider_load_key(
    provider: UnsafePointer[CryptoProvider],
    private_key: UnsafePointer[UInt8],
    private_key_len: Int,
    signing_key_out: UnsafePointer[UnsafePointer[SigningKey]],
) -> Result:
    """
    Load a private key from the provided PEM content using the crypto provider.

    `private_key` must point to a buffer of `private_key_len` bytes, containing
    a PEM-encoded private key. The exact formats supported will differ based on
    the crypto provider in use. The default providers support PKCS#1, PKCS#8 or
    SEC1 formats.

    When this function returns `rustls_result::Ok` a pointer to a `rustls_signing_key`
    is written to `signing_key_out`. The caller owns the returned `rustls_signing_key`
    and must free it with `rustls_signing_key_free`.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider],
            UnsafePointer[UInt8],
            Int,
            UnsafePointer[UnsafePointer[SigningKey]],
        ) -> UInt32
    ]("rustls_crypto_provider_load_key")(
        provider, private_key, private_key_len, signing_key_out
    )


fn crypto_provider_random(
    provider: UnsafePointer[CryptoProvider],
    buff: UnsafePointer[UInt8],
    len: Int,
) -> Result:
    """
    Write `len` bytes of cryptographically secure random data to `buff` using the crypto provider.

    `buff` must point to a buffer of at least `len` bytes. The caller maintains ownership
    of the buffer.

    Returns `RUSTLS_RESULT_OK` on success, or `RUSTLS_RESULT_GET_RANDOM_FAILED` on failure.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider],
            UnsafePointer[UInt8],
            Int,
        ) -> UInt32
    ]("rustls_crypto_provider_random")(provider, buff, len)


fn crypto_provider_free(provider: UnsafePointer[CryptoProvider]):
    """
    Frees the `rustls_crypto_provider`.

    Calling with `NULL` is fine.
    Must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[CryptoProvider]) -> None](
        "rustls_crypto_provider_free"
    )(provider)


fn default_crypto_provider_ciphersuites_len() -> Int:
    """
    Returns the number of ciphersuites the default process-wide crypto provider supports.

    You can use this to know the maximum allowed index for use with
    `rustls_default_crypto_provider_ciphersuites_get`.

    This function will return 0 if no process-wide default `rustls_crypto_provider` is available.
    """
    return _rustls.get_function[fn () -> Int](
        "rustls_default_crypto_provider_ciphersuites_len"
    )()


fn default_crypto_provider_ciphersuites_get(
    index: Int,
) -> UnsafePointer[SupportedCiphersuite]:
    """
    Retrieve a pointer to a supported ciphersuite of the default process-wide crypto provider.

    This function will return NULL if the `provider` is NULL, or if the index is out of bounds
    with respect to `rustls_default_crypto_provider_ciphersuites_len`.

    The lifetime of the returned `rustls_supported_ciphersuite` is static, as the process-wide
    default provider lives for as long as the process.
    """
    return _rustls.get_function[
        fn (Int) -> UnsafePointer[SupportedCiphersuite]
    ]("rustls_default_crypto_provider_ciphersuites_get")(index)


fn default_crypto_provider_random(
    buff: UnsafePointer[UInt8], len: Int
) -> Result:
    """
    Write `len` bytes of cryptographically secure random data to `buff` using the process-wide
    default crypto provider.

    `buff` must point to a buffer of at least `len` bytes. The caller maintains ownership
    of the buffer.

    Returns `RUSTLS_RESULT_OK` on success, and one of `RUSTLS_RESULT_NO_DEFAULT_CRYPTO_PROVIDER`
    or `RUSTLS_RESULT_GET_RANDOM_FAILED` on failure.
    """
    return _rustls.get_function[fn (UnsafePointer[UInt8], Int) -> Result](
        "rustls_default_crypto_provider_random"
    )(buff, len)


fn signing_key_free(signing_key: UnsafePointer[SigningKey]):
    """
    Frees the `rustls_signing_key`. This is safe to call with a `NULL` argument, but
    must not be called twice with the same value.
    """
    _rustls.get_function[fn (UnsafePointer[SigningKey]) -> None](
        "rustls_signing_key_free"
    )(signing_key)


fn error(
    result: UInt32,
    buf: UnsafePointer[Int8],
    len: Int,
    out_n: UnsafePointer[Int],
):
    """
    After a rustls function returns an error, you may call
    this to get a pointer to a buffer containing a detailed error
    message.

    The contents of the error buffer will be out_n bytes long,
    UTF-8 encoded, and not NUL-terminated.
    """
    _rustls.get_function[
        fn (UInt32, UnsafePointer[Int8], Int, UnsafePointer[Int]) -> None
    ]("rustls_error")(result, buf, len, out_n)


fn result_is_cert_error(result: UInt32) -> Bool:
    return _rustls.get_function[fn (UInt32) -> Bool](
        "rustls_result_is_cert_error"
    )(result)


fn log_level_str(level: LogLevel) -> StringRef:
    """
    Return a rustls_str containing the stringified version of a log level.
    """
    return _rustls.get_function[fn (LogLevel) -> StringRef](
        "rustls_log_level_str"
    )(level)


fn slice_slice_bytes_len(input: UnsafePointer[SliceSliceBytes]) -> Int:
    """
    Return the length of the outer slice. If the input pointer is NULL,
    returns 0.
    """
    return _rustls.get_function[fn (UnsafePointer[SliceSliceBytes]) -> Int](
        "rustls_slice_slice_bytes_len"
    )(input)


fn slice_slice_bytes_get(
    input: UnsafePointer[SliceSliceBytes], n: Int
) -> SliceBytes:
    """
    Retrieve the nth element from the input slice of slices.

    If the input pointer is NULL, or n is greater than the length
    of the `rustls_slice_slice_bytes`, returns rustls_slice_bytes{NULL, 0}.
    """
    return _rustls.get_function[
        fn (UnsafePointer[SliceSliceBytes], Int) -> SliceBytes
    ]("rustls_slice_slice_bytes_get")(input, n)


fn slice_str_len(input: UnsafePointer[SliceStr]) -> Int:
    """
    Return the length of the outer slice.

    If the input pointer is NULL, returns 0.
    """
    return _rustls.get_function[fn (UnsafePointer[SliceStr]) -> Int](
        "rustls_slice_str_len"
    )(input)


fn slice_str_get(input: UnsafePointer[SliceStr], n: Int) -> StringRef:
    """
    Retrieve the nth element from the input slice of `&str`s.

    If the input pointer is NULL, or n is greater than the length of the
    rustls_slice_str, returns rustls_str{NULL, 0}.
    """
    return _rustls.get_function[fn (UnsafePointer[SliceStr], Int) -> StringRef](
        "rustls_slice_str_get"
    )(input, n)


fn server_config_builder_new() -> UnsafePointer[ServerConfigBuilder]:
    """
    Create a rustls_server_config_builder using the process default crypto provider.

    Caller owns the memory and must eventually call rustls_server_config_builder_build,
    then free the resulting rustls_server_config.

    Alternatively, if an error occurs or, you don't wish to build a config, call
    `rustls_server_config_builder_free` to free the builder directly.

    This uses the process default provider's values for the cipher suites and key exchange
    groups, as well as safe defaults for protocol versions.
    """
    return _rustls.get_function[fn () -> UnsafePointer[ServerConfigBuilder]](
        "rustls_server_config_builder_new"
    )()


fn server_config_builder_new_custom(
    provider: UnsafePointer[CryptoProvider],
    versions: UnsafePointer[UInt16],
    tls_versions_len: Int,
    builder_out: UnsafePointer[UnsafePointer[ServerConfigBuilder]],
) -> Result:
    """
    Create a rustls_server_config_builder using the specified crypto provider.

    Caller owns the memory and must eventually call rustls_server_config_builder_build,
    then free the resulting rustls_server_config.

    Alternatively, if an error occurs or, you don't wish to build a config, call
    `rustls_server_config_builder_free` to free the builder directly.

    `tls_versions` set the TLS protocol versions to use when negotiating a TLS session.

    `tls_versions` is the version of the protocol, as defined in rfc8446,
    ch. 4.2.1 and end of ch. 5.1. Some values are defined in
    `rustls_tls_version` for convenience.

    `tls_versions` will only be used during the call and the application retains
    ownership. `tls_versions_len` is the number of consecutive `uint16_t` pointed
    to by `tls_versions`.

    Ciphersuites are configured separately via the crypto provider. See
    `rustls_crypto_provider_builder_set_cipher_suites` for more information.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[CryptoProvider],
            UnsafePointer[UInt16],
            Int,
            UnsafePointer[UnsafePointer[ServerConfigBuilder]],
        ) -> UInt32
    ]("rustls_server_config_builder_new_custom")(
        provider, versions, tls_versions_len, builder_out
    )


fn server_config_builder_set_client_verifier(
    builder: UnsafePointer[ServerConfigBuilder],
    verifier: UnsafePointer[ClientCertVerifier],
):
    """
    Create a rustls_server_config_builder for TLS sessions that may verify client
    certificates.

    This increases the refcount of `verifier` and doesn't take ownership.
    """
    _rustls.get_function[
        fn (
            UnsafePointer[ServerConfigBuilder],
            UnsafePointer[ClientCertVerifier],
        ) -> None
    ]("rustls_server_config_builder_set_client_verifier")(builder, verifier)


fn server_config_builder_free(
    config: UnsafePointer[ServerConfigBuilder],
):
    """
    "Free" a server_config_builder without building it into a rustls_server_config.

    Normally builders are built into rustls_server_configs via `rustls_server_config_builder_build`
    and may not be free'd or otherwise used afterwards.

    Use free only when the building of a config has to be aborted before a config
    was created.
    """
    return _rustls.get_function[
        fn (UnsafePointer[ServerConfigBuilder]) -> None
    ]("rustls_server_config_builder_free")(config)


fn server_config_builder_set_ignore_client_order(
    builder: UnsafePointer[ServerConfigBuilder], ignore: Bool
) -> Result:
    """
    With `ignore` != 0, the server will ignore the client ordering of cipher
    suites, aka preference, during handshake and respect its own ordering
    as configured.
    <https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html#structfield.ignore_client_order>
    """
    return _rustls.get_function[
        fn (UnsafePointer[ServerConfigBuilder], Bool) -> UInt32
    ]("rustls_server_config_builder_set_ignore_client_order")(builder, ignore)


fn server_config_builder_set_alpn_protocols(
    builder: UnsafePointer[ServerConfigBuilder],
    protocols: UnsafePointer[SliceBytes],
    len: Int,
) -> Result:
    """
    Set the ALPN protocol list to the given protocols.

    `protocols` must point to a buffer of `rustls_slice_bytes` (built by the caller)
    with `len` elements. Each element of the buffer must point to a slice of bytes that
    contains a single ALPN protocol from
    <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.

    This function makes a copy of the data in `protocols` and does not retain
    any pointers, so the caller can free the pointed-to memory after calling.

    <https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#structfield.alpn_protocols>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ServerConfigBuilder], UnsafePointer[SliceBytes], Int
        ) -> UInt32
    ]("rustls_server_config_builder_set_alpn_protocols")(
        builder, protocols, len
    )


fn server_config_builder_set_certified_keys(
    builder: UnsafePointer[ServerConfigBuilder],
    certified_keys: UnsafePointer[UnsafePointer[CertifiedKey]],
    certified_keys_len: Int,
) -> Result:
    """
    Provide the configuration a list of certificates where the connection
    will select the first one that is compatible with the client's signature
    verification capabilities.

    Servers that want to support both ECDSA and RSA certificates will want
    the ECSDA to go first in the list.

    The built configuration will keep a reference to all certified keys
    provided. The client may `rustls_certified_key_free()` afterwards
    without the configuration losing them. The same certified key may also
    be used in multiple configs.

    EXPERIMENTAL: installing a client_hello callback will replace any
    configured certified keys and vice versa.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ServerConfigBuilder],
            UnsafePointer[UnsafePointer[CertifiedKey]],
            Int,
        ) -> UInt32
    ]("rustls_server_config_builder_set_certified_keys")(
        builder, certified_keys, certified_keys_len
    )


fn server_config_builder_build(
    builder: UnsafePointer[ServerConfigBuilder],
    config_out: UnsafePointer[UnsafePointer[ServerConfig]],
) -> Result:
    """
    Turn a *rustls_server_config_builder (mutable) into a const *rustls_server_config
    (read-only). The constructed `rustls_server_config` will be written to the `config_out`
    pointer when this function returns `rustls_result::Ok`.

    This function may return an error if no process default crypto provider has been set
    and the builder was constructed using `rustls_server_config_builder_new`, or if no
    certificate resolver was set.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ServerConfigBuilder],
            UnsafePointer[UnsafePointer[ServerConfig]],
        ) -> UInt32
    ]("rustls_server_config_builder_build")(builder, config_out)


fn server_config_free(config: UnsafePointer[ServerConfig]):
    """
    "Free" a rustls_server_config previously returned from
    rustls_server_config_builder_build.

    Since rustls_server_config is actually an
    atomically reference-counted pointer, extant server connections may still
    hold an internal reference to the Rust object. However, C code must
    consider this pointer unusable after "free"ing it.
    Calling with NULL is fine. Must not be called twice with the same value.
    """
    return _rustls.get_function[fn (UnsafePointer[ServerConfig]) -> None](
        "rustls_server_config_free"
    )(config)


fn server_connection_new(
    config: UnsafePointer[ServerConfig],
    conn_out: UnsafePointer[UnsafePointer[Connection]],
) -> Result:
    """
    Create a new rustls_connection containing a server connection, and return it.

    It is returned in the output parameter `conn_out`.

    If this returns an error code, the memory pointed to by `conn_out` remains unchanged.

    If this returns a non-error, the memory pointed to by `conn_out` is modified to point
    at a valid rustls_connection

    The caller now owns the rustls_connection and must call `rustls_connection_free` when
    done with it.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ServerConfig],
            UnsafePointer[UnsafePointer[Connection]],
        ) -> UInt32
    ]("rustls_server_connection_new")(config, conn_out)


fn server_connection_get_server_name(
    conn: UnsafePointer[Connection],
    buf: UnsafePointer[UInt8],
    count: Int,
    out_n: UnsafePointer[Int],
) -> Result:
    """
    Copy the server name from the server name indication (SNI) extension to `buf`.

    `buf` can hold up  to `count` bytes, and the length of that server name in `out_n`.

    The string is stored in UTF-8 with no terminating NUL byte.

    Returns RUSTLS_RESULT_INSUFFICIENT_SIZE if the SNI hostname is longer than `count`.

    Returns Ok with *out_n == 0 if there is no SNI hostname available on this connection
    because it hasn't been processed yet, or because the client did not send SNI.
    <https://docs.rs/rustls/latest/rustls/server/struct.ServerConnection.html#method.server_name>
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[Connection],
            UnsafePointer[UInt8],
            Int,
            UnsafePointer[Int],
        ) -> UInt32
    ]("rustls_server_connection_get_server_name")(conn, buf, count, out_n)


fn server_config_builder_set_hello_callback(
    builder: UnsafePointer[ServerConfigBuilder], callback: ClientHelloCallback
) -> Result:
    """
    Register a callback to be invoked when a connection created from this config
    sees a TLS ClientHello message. If `userdata` has been set with
    rustls_connection_set_userdata, it will be passed to the callback.
    Otherwise the userdata param passed to the callback will be NULL.

    Any existing `ResolvesServerCert` implementation currently installed in the
    `rustls_server_config` will be replaced. This also means registering twice
    will overwrite the first registration. It is not permitted to pass a NULL
    value for `callback`.

    EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
    the rustls library is re-evaluating their current approach to client hello handling.
    Installing a client_hello callback will replace any configured certified keys
    and vice versa. Same holds true for the set_certified_keys variant.
    """
    return _rustls.get_function[
        fn (UnsafePointer[ServerConfigBuilder], ClientHelloCallback) -> UInt32
    ]("rustls_server_config_builder_set_hello_callback")(builder, callback)


fn client_hello_select_certified_key(
    hello: UnsafePointer[ClientHello],
    certified_keys: UnsafePointer[UnsafePointer[CertifiedKey]],
    certified_keys_len: Int,
    out_key: UnsafePointer[UnsafePointer[CertifiedKey]],
) -> Result:
    """
    Select a `rustls_certified_key` from the list that matches the cryptographic
    parameters of a TLS client hello.

    Note that this does not do any SNI matching. The input certificates should
    already have been filtered to ones matching the SNI from the client hello.

    This is intended for servers that are configured with several keys for the
    same domain name(s), for example ECDSA and RSA types. The presented keys are
    inspected in the order given and keys first in the list are given preference,
    all else being equal. However rustls is free to choose whichever it considers
    to be the best key with its knowledge about security issues and possible future
    extensions of the protocol.

    Return RUSTLS_RESULT_OK if a key was selected and RUSTLS_RESULT_NOT_FOUND
    if none was suitable.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientHello],
            UnsafePointer[UnsafePointer[CertifiedKey]],
            Int,
            UnsafePointer[UnsafePointer[CertifiedKey]],
        ) -> UInt32
    ]("rustls_client_hello_select_certified_key")(
        hello, certified_keys, certified_keys_len, out_key
    )


fn server_config_builder_set_persistence(
    builder: UnsafePointer[ServerConfigBuilder],
    get_cb: SessionStoreGetCallback,
    put_cb: SessionStorePutCallback,
) -> Result:
    """
    Register callbacks for persistence of TLS session IDs and secrets. Both
    keys and values are highly sensitive data, containing enough information
    to break the security of the connections involved.

    If `userdata` has been set with rustls_connection_set_userdata, it
    will be passed to the callbacks. Otherwise the userdata param passed to
    the callbacks will be NULL.
    """
    return _rustls.get_function[
        fn (
            UnsafePointer[ServerConfigBuilder],
            SessionStoreGetCallback,
            SessionStorePutCallback,
        ) -> UInt32
    ]("rustls_server_config_builder_set_persistence")(builder, get_cb, put_cb)
