from sys import ffi
import os

var _rustls = ffi.DLHandle(os.getenv("CONDA_PREFIX") + "/share/mojo-rustls-ffi/librustls.dylib", ffi.RTLD.LAZY)

struct ClientConfig:
    pass

struct RootCertStoreBuilder:
    pass

struct RootCertStore:
    pass

struct WebPkiServerCertVerifierBuilder:
    pass

struct ServerCertVerifier:
    pass


fn new_client_config() -> UnsafePointer[ClientConfig]:
    return _rustls.get_function[
        fn () -> UnsafePointer[ClientConfig]
    ]("rustls_client_config_builder_new")()

fn new_root_cert_store_builder() -> UnsafePointer[RootCertStoreBuilder]:
    return _rustls.get_function[
        fn () -> UnsafePointer[RootCertStoreBuilder]
    ]("rustls_root_cert_store_builder_new")()

fn load_roots_from_file(builder: UnsafePointer[RootCertStoreBuilder], file_path: UnsafePointer[UInt8], optional: Bool) -> Int:
    return _rustls.get_function[
        fn (UnsafePointer[RootCertStoreBuilder], UnsafePointer[UInt8], Bool) -> Int
    ]("rustls_root_cert_store_builder_load_roots_from_file")(builder, file_path, optional)


struct RustlsClientConfig:
    var _handle: UnsafePointer[ClientConfig]

    fn __init__(inout self):
        self._handle = new_client_config()
