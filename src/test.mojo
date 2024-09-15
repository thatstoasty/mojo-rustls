from rustls import new_root_cert_store_builder, load_roots_from_file, RustlsClientConfig


fn main():
    var cert_path = "/etc/ssl/cert.pem"
    var config = RustlsClientConfig()

    var root_cert_store_builder = new_root_cert_store_builder()
    var result = load_roots_from_file(root_cert_store_builder, cert_path.unsafe_ptr(), False)

    print("Result: ", result)