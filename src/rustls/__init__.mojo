from sys import ffi
import os

alias RustlsResult = Int
var _rustls = ffi.DLHandle(os.getenv("CONDA_PREFIX") + "/share/mojo-rustls-ffi/librustls.dylib", ffi.RTLD.LAZY)

@value
struct SliceBytes():
    var data: UnsafePointer[UInt8]
    var len: Int
    # var phantom: PhantomData<&'a [u8]>,


struct WebPkiServerCertVerifierBuilder:
    pass


fn new_root_cert_store_builder() -> UnsafePointer[RootCertStoreBuilder]:
    return _rustls.get_function[fn () -> UnsafePointer[RootCertStoreBuilder]]("rustls_root_cert_store_builder_new")()


fn load_roots_from_file(
    builder: UnsafePointer[RootCertStoreBuilder], file_path: UnsafePointer[UInt8], optional: Bool
) -> RustlsResult:
    return _rustls.get_function[fn (UnsafePointer[RootCertStoreBuilder], UnsafePointer[UInt8], Bool) -> RustlsResult](
        "rustls_root_cert_store_builder_load_roots_from_file"
    )(builder, file_path, optional)


# Cipher


struct RootCertStoreBuilder:
    pass


struct RootCertStore:
    pass


fn build_root_cert_store_builder(
    builder: UnsafePointer[RootCertStoreBuilder], root_cert_store_out: UnsafePointer[UnsafePointer[RootCertStore]]
) -> RustlsResult:
    return _rustls.get_function[
        fn (
            builder: UnsafePointer[RootCertStoreBuilder],
            root_cert_store_out: UnsafePointer[UnsafePointer[RootCertStore]],
        ) -> RustlsResult
    ]("rustls_root_cert_store_builder_build")(builder, root_cert_store_out)


struct ServerCertVerifier:
    pass


fn new_web_pki_server_cert_verifier_builder(
    store: UnsafePointer[RootCertStore],
) -> UnsafePointer[WebPkiServerCertVerifierBuilder]:
    return _rustls.get_function[fn (UnsafePointer[RootCertStore]) -> UnsafePointer[WebPkiServerCertVerifierBuilder]](
        "rustls_web_pki_server_cert_verifier_builder_new"
    )(store)


fn build_web_pki_server_cert_verifier_builder(
    builder: UnsafePointer[WebPkiServerCertVerifierBuilder],
    verifier_out: UnsafePointer[UnsafePointer[ServerCertVerifier]],
) -> RustlsResult:
    return _rustls.get_function[
        fn (
            UnsafePointer[WebPkiServerCertVerifierBuilder], UnsafePointer[UnsafePointer[ServerCertVerifier]]
        ) -> RustlsResult
    ]("rustls_web_pki_server_cert_verifier_builder_build")(builder, verifier_out)


fn client_config_builder_set_server_verifier(
    builder: UnsafePointer[ClientConfigBuilder],
    verifier: UnsafePointer[ServerCertVerifier],
) -> None:
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder], UnsafePointer[ServerCertVerifier]
        ) -> None
    ]("rustls_client_config_builder_set_server_verifier")(builder, verifier)


fn client_config_builder_set_alpn_protocols(
    builder: UnsafePointer[ClientConfigBuilder],
    protocols: UnsafePointer[String],
    len: UInt,
) -> RustlsResult:
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder], UnsafePointer[String], UInt
        ) -> RustlsResult
    ]("rustls_client_config_builder_set_alpn_protocols")(builder, protocols, len)


fn build_client_config_builder(
    builder: UnsafePointer[ClientConfigBuilder],
    config_out: UnsafePointer[UnsafePointer[ClientConfig]],
) -> RustlsResult:
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfigBuilder], UnsafePointer[UnsafePointer[ClientConfig]]
        ) -> RustlsResult
    ]("rustls_client_config_builder_build")(builder, config_out)

# Connection
@value
struct LogParams:
    var level: UInt
    var message: String


struct RustlsConnection:
    pass


struct Connection:
    var conn: RustlsConnection
    var userdata: UnsafePointer[UInt8]
    var log_callback: fn (userdata: UnsafePointer[UInt8], params: UnsafePointer[LogParams]) -> None


# Client
struct ClientConfig:
    pass

@value
struct ClientConfigBuilder:
    pass


fn new_client_config_builder() -> UnsafePointer[ClientConfigBuilder]:
    return _rustls.get_function[fn () -> UnsafePointer[ClientConfigBuilder]]("rustls_client_config_builder_new")()


fn new_client_connection(
    config: UnsafePointer[ClientConfig],
    server_name: UnsafePointer[UInt8],
    conn_out: UnsafePointer[UnsafePointer[Connection]],
) -> None:
    return _rustls.get_function[
        fn (
            UnsafePointer[ClientConfig], UnsafePointer[UInt8], UnsafePointer[UnsafePointer[Connection]]
        ) -> None
    ]("rustls_client_connection_new")(config, server_name, conn_out)


struct RustlsClientConfig:
    var _handle: UnsafePointer[ClientConfigBuilder]

    fn __init__(inout self):
        self._handle = new_client_config()
