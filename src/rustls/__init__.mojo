import . _cffi as _c
from pathlib import Path
from os import PathLike
from utils import StaticString, StringSlice
from memory import Span, ArcPointer, UnsafePointer
from ._cffi import TlsVersion, LogLevel


struct Accepted:
    """
    A parsed ClientHello produced by a rustls_acceptor.

    It is used to check server name indication (SNI), ALPN protocols,
    signature schemes, and cipher suites. It can be combined with a
    `rustls_server_config` to build a `rustls_connection`.
    """


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
    """

    var _handle: UnsafePointer[_c.Acceptor]

    fn __init__(inout self):
        self._handle = _c.acceptor_new()

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.Acceptor]()

    fn __del__(owned self):
        _c.acceptor_free(self._handle)


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

    var _handle: UnsafePointer[_c.CertifiedKey]

    fn __init__(
        inout self, cert_chain: Span[UInt8], private_key: Span[UInt8]
    ) raises:
        self._handle = UnsafePointer[_c.CertifiedKey]()
        result = _c.certified_key_build(
            cert_chain.unsafe_ptr(),
            len(cert_chain),
            private_key.unsafe_ptr(),
            len(private_key),
            UnsafePointer.address_of(self._handle),
        )
        if result != _c.Result.ok:
            raise Error("failed to create certified key" + str(result.value))

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.CertifiedKey]()

    fn __del__(owned self):
        _c.certified_key_free(self._handle)


struct ClientCertVerifier:
    """
    A built client certificate verifier that can be provided to a `rustls_server_config_builder`
    with `rustls_server_config_builder_set_client_verifier`.
    """

    var _handle: UnsafePointer[_c.ClientCertVerifier]


struct ClientConfig:
    """
    A client config that is done being constructed and is now read-only.

    Under the hood, this object corresponds to an `Arc<ClientConfig>`.
    <https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html>
    """

    var _handle: UnsafePointer[_c.ClientConfig]

    fn __init__(inout self, *, unsafe_ptr: UnsafePointer[_c.ClientConfig]):
        self._handle = unsafe_ptr

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.ClientConfig]()

    fn __del__(owned self):
        _c.client_config_free(self._handle)


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

    var _handle: UnsafePointer[_c.ClientConfigBuilder]

    fn __init__(inout self):
        self._handle = _c.client_config_builder_new()

    fn __init__(
        inout self, provider: CryptoProvider, tls_versions: Span[UInt16]
    ) raises:
        self._handle = UnsafePointer[_c.ClientConfigBuilder]()
        result = _c.client_config_builder_new_custom(
            provider._handle,
            tls_versions.unsafe_ptr(),
            len(tls_versions),
            UnsafePointer.address_of(self._handle),
        )
        if result != _c.Result.ok:
            raise Error("failed to create crypto provider" + str(result.value))

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.ClientConfigBuilder]()

    fn __del__(owned self):
        _c.client_config_builder_free(self._handle)

    fn set_alpn_protocols[
        lt: Origin
    ](inout self, protocols: Span[Span[UInt8, lt]]) raises:
        protocols_ = List[_c.SliceBytes](capacity=len(protocols))
        for p in protocols:
            protocols_.append(_c.SliceBytes(p[].unsafe_ptr(), len(p[])))
        result = _c.client_config_builder_set_alpn_protocols(
            self._handle, protocols_.unsafe_ptr(), len(protocols_)
        )
        if result != _c.Result.ok:
            raise Error("failed to set alpn protocols" + str(result.value))

    fn set_server_verifier(inout self, verifier: ServerCertVerifier):
        _c.client_config_builder_set_server_verifier(
            self._handle, verifier._handle
        )

    fn set_enable_sni(inout self, enable: Bool):
        _c.client_config_builder_set_enable_sni(self._handle, enable)

    fn set_certified_key(
        inout self, certified_keys: Span[ArcPointer[CertifiedKey]]
    ) raises:
        keys = List[UnsafePointer[_c.CertifiedKey]](
            capacity=len(certified_keys)
        )

        for k in certified_keys:
            keys.append(k[][]._handle)

        result = _c.client_config_builder_set_certified_key(
            self._handle, keys.unsafe_ptr(), len(keys)
        )
        _ = keys^
        if result != _c.Result.ok:
            raise Error("failed to set certified key" + str(result.value))

    fn build(owned self) raises -> ClientConfig:
        config = ClientConfig(unsafe_ptr=UnsafePointer[_c.ClientConfig]())
        result = _c.client_config_builder_build(
            self._handle, UnsafePointer.address_of(config._handle)
        )
        self._handle = UnsafePointer[_c.ClientConfigBuilder]()
        if result != _c.Result.ok:
            raise Error("failed to build client config" + str(result.value))
        return config^


struct ClientConnection:
    var _handle: UnsafePointer[_c.Connection]

    fn __init__(inout self, config: ClientConfig, server_name: String) raises:
        self._handle = UnsafePointer[_c.Connection]()
        result = _c.client_connection_new(
            config._handle,
            server_name.unsafe_cstr_ptr(),
            UnsafePointer.address_of(self._handle),
        )
        if result != _c.Result.ok:
            raise Error(
                "failed to build client connection: " + str(result.value)
            )

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.Connection]()

    fn __del__(owned self):
        _c.connection_free(self._handle)

    fn set_log_callback[cb: fn (LogLevel, StringSlice) -> None](inout self):
        fn log(
            userdata: UnsafePointer[NoneType],
            params: UnsafePointer[_c.LogParams],
        ):
            cb(
                params[].level,
                StaticString(unsafe_from_utf8_strref=params[].message),
            )

        _c.connection_set_log_callback(self._handle, log)

    fn readable(self) -> Bool:
        return _c.connection_wants_read(self._handle)

    fn read_tls(inout self, buf: Span[UInt8]) raises:
        pass

    fn write_tls_into[
        lifetime: MutableLifetime
    ](inout self, buf: Span[UInt8, lifetime]) raises:
        pass

    fn writable(self) -> Bool:
        return _c.connection_wants_write(self._handle)


struct CryptoProvider:
    """
    A representation of a Rustls [`CryptoProvider`].
    """

    var _handle: UnsafePointer[_c.CryptoProvider]

    fn __init__(inout self, *, unsafe_ptr: UnsafePointer[_c.CryptoProvider]):
        self._handle = unsafe_ptr

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.CryptoProvider]()

    fn __del__(owned self):
        _c.crypto_provider_free(self._handle)


struct CryptoProviderBuilder:
    """
    A `CryptoProvider` builder.
    """

    var _handle: UnsafePointer[_c.CryptoProviderBuilder]

    fn __init__(inout self) raises:
        self._handle = UnsafePointer[_c.CryptoProviderBuilder]()
        result = _c.crypto_provider_builder_new_from_default(
            UnsafePointer.address_of(self._handle)
        )
        if result != _c.Result.ok:
            raise Error(
                "Failed to build crypto provider builder: " + str(result.value)
            )

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.CryptoProviderBuilder]()

    fn __del__(owned self):
        _c.crypto_provider_builder_free(self._handle)

    fn set_cipher_suites(
        self, cipher_suites: Span[SupportedCiphersuite]
    ) raises:
        result = _c.crypto_provider_builder_set_cipher_suites(
            self._handle,
            UnsafePointer.address_of(cipher_suites).bitcast[
                UnsafePointer[_c.SupportedCiphersuite]
            ](),
            len(cipher_suites),
        )
        if result != _c.Result.ok:
            raise Error("Failed to set ciphersuite: " + str(result.value))

    fn build(owned self) raises -> CryptoProvider:
        provider = CryptoProvider(unsafe_ptr=UnsafePointer[_c.CryptoProvider]())
        result = _c.crypto_provider_builder_build(
            self._handle, UnsafePointer.address_of(provider._handle)
        )
        self._handle = UnsafePointer[_c.CryptoProviderBuilder]()
        if result != _c.Result.ok:
            raise Error("Failed build crypto provider: " + str(result.value))
        return provider^


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

    var _handle: UnsafePointer[_c.RootCertStore]

    fn __init__(inout self, *, unsafe_ptr: UnsafePointer[_c.RootCertStore]):
        self._handle = unsafe_ptr

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.RootCertStore]()

    fn __del__(owned self):
        _c.root_cert_store_free(self._handle)


struct RootCertStoreBuilder:
    """
    A `rustls_root_cert_store` being constructed.

    A builder can be modified by adding trust anchor root certificates with
    `rustls_root_cert_store_builder_add_pem`. Once you're done adding root certificates,
    call `rustls_root_cert_store_builder_build` to turn it into a `rustls_root_cert_store`.
    This object is not safe for concurrent mutation.
    """

    var _handle: UnsafePointer[_c.RootCertStoreBuilder]

    fn __init__(inout self):
        self._handle = _c.root_cert_store_builder_new()

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.RootCertStoreBuilder]()

    fn __del__(owned self):
        _c.root_cert_store_builder_free(self._handle)

    fn load_roots_from_file[P: PathLike](inout self, file: P) raises:
        path = file.__fspath__()
        result = _c.root_cert_store_builder_load_roots_from_file(
            self._handle, path.unsafe_cstr_ptr(), True
        )
        _ = path^
        if result != _c.Result.ok:
            raise Error("Failed to load roots from file:" + str(result.value))

    fn add_pem(inout self, pem: Span[UInt8]) raises:
        result = _c.root_cert_store_builder_add_pem(
            self._handle, pem.unsafe_ptr(), len(pem), True
        )
        if result != _c.Result.ok:
            raise Error("Failed to load roots from file:" + str(result.value))

    fn build(owned self) raises -> RootCertStore:
        store = RootCertStore(unsafe_ptr=UnsafePointer[_c.RootCertStore]())
        result = _c.root_cert_store_builder_build(
            self._handle, UnsafePointer.address_of(store._handle)
        )
        self._handle = UnsafePointer[_c.RootCertStoreBuilder]()
        if result != _c.Result.ok:
            raise Error("failed to build root cert store: " + str(result.value))
        return store^


struct ServerCertVerifier:
    """
    A built server certificate verifier that can be provided to a `rustls_client_config_builder`
    with `rustls_client_config_builder_set_server_verifier`.
    """

    var _handle: UnsafePointer[_c.ServerCertVerifier]

    fn __init__(
        inout self, *, unsafe_ptr: UnsafePointer[_c.ServerCertVerifier]
    ):
        self._handle = unsafe_ptr

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.ServerCertVerifier]()

    fn __del__(owned self):
        _c.server_cert_verifier_free(self._handle)


struct ServerConfig:
    """
    A server config that is done being constructed and is now read-only.

    Under the hood, this object corresponds to an `Arc<ServerConfig>`.
    <https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html>
    """

    var _handle: UnsafePointer[_c.ServerConfig]

    fn __init__(inout self, *, unsafe_ptr: UnsafePointer[_c.ServerConfig]):
        self._handle = unsafe_ptr

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.ServerConfig]()

    fn __del__(owned self):
        _c.server_config_free(self._handle)


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

    var _handle: UnsafePointer[_c.ServerConfigBuilder]

    fn __init__(inout self):
        self._handle = _c.server_config_builder_new()

    fn __del__(owned self):
        _c.server_config_builder_free(self._handle)

    fn set_client_verifier(inout self, verifier: ClientCertVerifier):
        _c.server_config_builder_set_client_verifier(
            self._handle, verifier._handle
        )

    fn set_ignore_client_order(inout self, ignore: Bool) raises:
        result = _c.server_config_builder_set_ignore_client_order(
            self._handle, ignore
        )
        if result != _c.Result.ok:
            raise Error("failed to set ignore client order" + str(result.value))

    fn set_alpn_protocols[
        lt: ImmutableLifetime
    ](inout self, protocols: Span[Span[UInt8, lt]]) raises:
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
        protocols_ = List[_c.SliceBytes](capacity=len(protocols))
        for p in protocols:
            protocols_.append(_c.SliceBytes(p[].unsafe_ptr(), len(p[])))
        result = _c.server_config_builder_set_alpn_protocols(
            self._handle, protocols_.unsafe_ptr(), len(protocols_)
        )
        _ = protocols_
        if result != _c.Result.ok:
            raise Error("failed to set alpn protocol" + str(result.value))

    fn set_certified_keys(
        inout self, certified_keys: Span[ArcPointer[CertifiedKey]]
    ) raises:
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
        keys = List[UnsafePointer[_c.CertifiedKey]]()
        for k in certified_keys:
            keys.append(k[][]._handle)
        result = _c.server_config_builder_set_certified_keys(
            self._handle, keys.unsafe_ptr(), len(keys)
        )
        _ = keys^
        if result != _c.Result.ok:
            raise Error("failed to set certified key" + str(result.value))

    fn build(owned self) raises -> ServerConfig:
        """
        Turn a *rustls_server_config_builder (mutable) into a const *rustls_server_config
        (read-only). The constructed `rustls_server_config` will be written to the `config_out`
        pointer when this function returns `rustls_result::Ok`.

        This function may return an error if no process default crypto provider has been set
        and the builder was constructed using `rustls_server_config_builder_new`, or if no
        certificate resolver was set.
        """
        config = ServerConfig(unsafe_ptr=UnsafePointer[_c.ServerConfig]())
        result = _c.server_config_builder_build(
            self._handle, UnsafePointer.address_of(config._handle)
        )
        # Is this right?
        self._handle = UnsafePointer[_c.ServerConfigBuilder]()
        if result != _c.Result.ok:
            raise Error("failed to build server config" + str(result.value))
        return config^


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


fn default_crypto_provider_ciphersuites() -> SupportedCiphersuitesIterator:
    return SupportedCiphersuitesIterator()


@value
struct SupportedCiphersuitesIterator:
    """
    An iterator over rustls ciphersuites.
    """

    var index: Int
    var len: Int

    fn __init__(inout self):
        self.index = 0
        self.len = _c.default_crypto_provider_ciphersuites_len()

    fn __iter__(self) -> Self:
        return self

    fn __next__(
        inout self,
    ) -> SupportedCiphersuite:
        result = SupportedCiphersuite(
            unsafe_ptr=_c.default_crypto_provider_ciphersuites_get(self.index)
        )
        self.index += 1
        return result
    
    fn __has_next__(self) -> Bool:
        return self.index < self.len

    fn __len__(self) -> Int:
        return self.len - self.index


struct SupportedCiphersuite:
    """
    A cipher suite supported by rustls.
    """

    var _handle: UnsafePointer[_c.SupportedCiphersuite]

    fn __init__(
        inout self, *, unsafe_ptr: UnsafePointer[_c.SupportedCiphersuite]
    ):
        self._handle = unsafe_ptr

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle

    fn __copyinit__(inout self, rhs: Self):
        self._handle = rhs._handle

    fn __bool__(inout self) -> Bool:
        return self._handle

    fn get_suite(self) -> UInt16:
        return _c.supported_ciphersuite_get_suite(self._handle)

    fn get_name(self) -> StaticString:
        return _c.supported_ciphersuite_get_name(self._handle)

    fn protocol_version(self) -> TlsVersion:
        return _c.supported_ciphersuite_protocol_version(self._handle)


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

    var _handle: UnsafePointer[_c.WebPkiServerCertVerifierBuilder]

    fn __init__(inout self, store: RootCertStore):
        self._handle = _c.web_pki_server_cert_verifier_builder_new(
            store._handle
        )

    fn __moveinit__(inout self, owned rhs: Self):
        self._handle = rhs._handle
        rhs._handle = UnsafePointer[_c.WebPkiServerCertVerifierBuilder]()

    fn __del__(owned self):
        _c.web_pki_server_cert_verifier_builder_free(self._handle)

    fn build(owned self) raises -> ServerCertVerifier:
        verifier = ServerCertVerifier(
            unsafe_ptr=UnsafePointer[_c.ServerCertVerifier]()
        )
        result = _c.web_pki_server_cert_verifier_builder_build(
            self._handle, UnsafePointer.address_of(verifier._handle)
        )
        self._handle = UnsafePointer[_c.WebPkiServerCertVerifierBuilder]()
        if result != _c.Result.ok:
            raise Error(
                "failed to build server cert verifier " + str(result.value)
            )
        return verifier^
