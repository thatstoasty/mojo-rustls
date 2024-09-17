from src.rustls import *
from src.libc import *

fn main():
    var cert_path = to_char_ptr("/etc/ssl/cert.pem")

    var config = RustlsClientConfig()   

    var root_cert_store_builder = new_root_cert_store_builder()
    var result = load_roots_from_file(root_cert_store_builder, cert_path, False)

    print("Result: ", result)
    # const char *hostname = argv[1];
    # const char *port = argv[2];
    # const char *path = argv[3];

    # /* Set this global variable for logging purposes. */
    # programname = "client";

    # const struct rustls_crypto_provider *custom_provider = NULL;
    # struct rustls_client_config_builder *config_builder = NULL;
    # struct rustls_root_cert_store_builder *server_cert_root_store_builder = NULL;
    # const struct rustls_root_cert_store *server_cert_root_store = NULL;
    # const struct rustls_client_config *client_config = NULL;
    # struct rustls_web_pki_server_cert_verifier_builder
    #     *server_cert_verifier_builder = NULL;
    # struct rustls_server_cert_verifier *server_cert_verifier = NULL;
    # struct rustls_slice_bytes alpn_http11;
    # const struct rustls_certified_key *certified_key = NULL;

    # alpn_http11.data = (unsigned char *)"http/1.1";
    # alpn_http11.len = 8;

    # #ifdef _WIN32
    # WSADATA wsa;
    # WSAStartup(MAKEWORD(1, 1), &wsa);
    # setmode(STDOUT_FILENO, O_BINARY);
    # #endif

    # const char *custom_ciphersuite_name = getenv("RUSTLS_CIPHERSUITE");
    # if(custom_ciphersuite_name != NULL) {
    #     custom_provider =
    #     default_provider_with_custom_ciphersuite(custom_ciphersuite_name);
    #     if(custom_provider == NULL) {
    #     goto cleanup;
    #     }
    #     printf("customized to use ciphersuite: %s\n", custom_ciphersuite_name);

    #     result = rustls_client_config_builder_new_custom(custom_provider,
    #                                                     default_tls_versions,
    #                                                     default_tls_versions_len,
    #                                                     &config_builder);
    #     if(result != RUSTLS_RESULT_OK) {
    #     print_error("creating client config builder", result);
    #     goto cleanup;
    #     }
    # }
    # else {
    #     config_builder = rustls_client_config_builder_new();
    # }

    # if(getenv("RUSTLS_PLATFORM_VERIFIER")) {
    #     result = rustls_platform_server_cert_verifier(&server_cert_verifier);
    #     if(result != RUSTLS_RESULT_OK) {
    #     fprintf(stderr, "client: failed to construct platform verifier\n");
    #     goto cleanup;
    #     }
    #     rustls_client_config_builder_set_server_verifier(config_builder,
    #                                                     server_cert_verifier);
    # }
    # else if(getenv("CA_FILE")) {
    #     server_cert_root_store_builder = rustls_root_cert_store_builder_new();
    #     result = rustls_root_cert_store_builder_load_roots_from_file(
    #     server_cert_root_store_builder, getenv("CA_FILE"), true);
    #     if(result != RUSTLS_RESULT_OK) {
    #     print_error("loading trusted certificates", result);
    #     goto cleanup;
    #     }
    #     result = rustls_root_cert_store_builder_build(
    #     server_cert_root_store_builder, &server_cert_root_store);
    #     if(result != RUSTLS_RESULT_OK) {
    #     goto cleanup;
    #     }
    #     server_cert_verifier_builder =
    #     rustls_web_pki_server_cert_verifier_builder_new(server_cert_root_store);

    #     result = rustls_web_pki_server_cert_verifier_builder_build(
    #     server_cert_verifier_builder, &server_cert_verifier);
    #     if(result != RUSTLS_RESULT_OK) {
    #     goto cleanup;
    #     }
    #     rustls_client_config_builder_set_server_verifier(config_builder,
    #                                                     server_cert_verifier);
    # }
    # else if(getenv("NO_CHECK_CERTIFICATE")) {
    #     rustls_client_config_builder_dangerous_set_certificate_verifier(
    #     config_builder, verify);
    # }
    # else {
    #     fprintf(stderr,
    #             "client: must set either RUSTLS_PLATFORM_VERIFIER or CA_FILE or "
    #             "NO_CHECK_CERTIFICATE env var\n");
    #     goto cleanup;
    # }

    # char *auth_cert = getenv("AUTH_CERT");
    # char *auth_key = getenv("AUTH_KEY");
    # if((auth_cert && !auth_key) || (!auth_cert && auth_key)) {
    #     fprintf(
    #     stderr,
    #     "client: must set both AUTH_CERT and AUTH_KEY env vars, or neither\n");
    #     goto cleanup;
    # }
    # else if(auth_cert && auth_key) {
    #     certified_key = load_cert_and_key(auth_cert, auth_key);
    #     if(certified_key == NULL) {
    #     goto cleanup;
    #     }
    #     rustls_client_config_builder_set_certified_key(
    #     config_builder, &certified_key, 1);
    # }

    # rustls_client_config_builder_set_alpn_protocols(
    #     config_builder, &alpn_http11, 1);

    # result = rustls_client_config_builder_build(config_builder, &client_config);
    # if(result != RUSTLS_RESULT_OK) {
    #     print_error("building client config", result);
    #     goto cleanup;
    # }

    # int i;
    # for(i = 0; i < 3; i++) {
    #     result = do_request(client_config, hostname, port, path);
    #     if(result != 0) {
    #     goto cleanup;
    #     }
    # }

    # // Success!
    # ret = 0;

    # cleanup:
    # rustls_root_cert_store_builder_free(server_cert_root_store_builder);
    # rustls_root_cert_store_free(server_cert_root_store);
    # rustls_web_pki_server_cert_verifier_builder_free(
    #     server_cert_verifier_builder);
    # rustls_server_cert_verifier_free(server_cert_verifier);
    # rustls_certified_key_free(certified_key);
    # rustls_client_config_free(client_config);
    # rustls_crypto_provider_free(custom_provider);

