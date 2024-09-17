from rustls import (
    RustlsClientConfig,
    Connection,
    RootCertStore,
    ServerCertVerifier,
    ClientConfigBuilder,
    ClientConfig,
    SliceBytes,
    RustlsResult,
    ConnData,
    new_root_cert_store_builder,
    load_roots_from_file,
    new_client_connection,
    new_client_config_builder,
    build_root_cert_store_builder,
    new_web_pki_server_cert_verifier_builder,
    build_web_pki_server_cert_verifier_builder,
    client_config_builder_set_server_verifier,
    client_config_builder_set_alpn_protocols,
    build_client_config_builder,
    rustls_connection_set_userdata,
    rustls_connection_set_log_callback,
)
import os
from sys import exit
from memory.memory import memset
from sys.info import sizeof
from sys.ffi import external_call
from lightbug_http.sys.net import create_connection
from libc import AF_INET, SOCK_STREAM, AI_PASSIVE, to_char_ptr, socket

fn do_request(client_config: UnsafePointer[ClientConfig], host: String, port: String, path: String) raises -> RustlsResult:
    var rconn = UnsafePointer[Connection]()
    var ret: RustlsResult = 1
    var fd = socket(AF_INET, SOCK_STREAM, 0)
    var connection = create_connection(fd, host, atol(port))
    if fd < 0:
        print("Failed to create connection")
        return ret

    var result = new_client_connection(client_config, host.unsafe_ptr(), UnsafePointer.address_of(rconn))
    if result != 7000:  # Assuming 7000 is RUSTLS_RESULT_OK
        print("failed to create new client connection, Result: ", result)
        return result

    var conn = ConnData(rconn, fd.__int__(), "verify_arg", SliceBytes(UnsafePointer[UInt8](), 0))

    rustls_connection_set_userdata(rconn, UnsafePointer[ConnData].address_of(conn))
    # rustls_connection_set_log_callback(rconn, log_cb)

    ret = send_request_and_read_response(UnsafePointer[ConnData].address_of(conn), rconn, host, path)
    if ret != 7000:
        return ret

    # # Cleanup
    # external_call["rustls_connection_free"](rconn)
    # if fd > 0:
    #     os.close(fd)
    # if conn.data.data != None:
    #     free(conn.data.data)

    return 7000  # Assuming 7000 is RUSTLS_RESULT_OK

fn log_cb(level: Int, message: String):
    print("Log level:", level, "Message:", message)

fn send_request_and_read_response(conn: UnsafePointer[ConnData], rconn: UnsafePointer[Connection], hostname: String, path: String) -> RustlsResult:
    # Implement this function based on your requirements
    return 7000  # Placeholder return value


# int
# do_request(const struct rustls_client_config *client_config,
#            const char *hostname, const char *port,
#            const char *path) // NOLINT(bugprone-easily-swappable-parameters)
# {
#   struct rustls_connection *rconn = NULL;
#   struct conndata *conn = NULL;
#   int ret = 1;
#   int sockfd = make_conn(hostname, port);
#   if(sockfd < 0) {
#     // No perror because make_conn printed error already.
#     goto cleanup;
#   }

#   rustls_result result =
#     rustls_client_connection_new(client_config, hostname, &rconn);
#   if(result != RUSTLS_RESULT_OK) {
#     print_error("client_connection_new", result);
#     goto cleanup;
#   }

#   conn = calloc(1, sizeof(struct conndata));
#   if(conn == NULL) {
#     goto cleanup;
#   }
#   conn->rconn = rconn;
#   conn->fd = sockfd;
#   conn->verify_arg = "verify_arg";

#   rustls_connection_set_userdata(rconn, conn);
#   rustls_connection_set_log_callback(rconn, log_cb);

#   ret = send_request_and_read_response(conn, rconn, hostname, path);
#   if(ret != RUSTLS_RESULT_OK) {
#     goto cleanup;
#   }

#   ret = 0;

# cleanup:
#   rustls_connection_free(rconn);
#   if(sockfd > 0) {
#     close(sockfd);
#   }
#   if(conn != NULL) {
#     if(conn->data.data != NULL) {
#       free(conn->data.data);
#     }
#     free(conn);
#   }
#   return ret;
# }


fn main():
    var cert_path = "/etc/ssl/cert.pem"
    if not os.setenv("CA_FILE", cert_path):
        print("Failed to set CA_FILE environment variable")
        exit(1)

    # var config = RustlsClientConfig()
    var config_builder = new_client_config_builder()

    var server_cert_root_store_builder = new_root_cert_store_builder()
    var result = load_roots_from_file(server_cert_root_store_builder, cert_path.unsafe_ptr(), False)
    if result != 7000:
        print("failed to load roots from file, Result: ", result)
        exit(1)

    var server_cert_root_store = UnsafePointer[RootCertStore]()
    result = build_root_cert_store_builder(server_cert_root_store_builder, UnsafePointer.address_of(server_cert_root_store))
    if result != 7000:
        print("failed to build cert store, Result: ", result)
        exit(1)

    var server_cert_verifier_builder = new_web_pki_server_cert_verifier_builder(server_cert_root_store)
    var server_cert_verifier = UnsafePointer[ServerCertVerifier]()
    result = build_web_pki_server_cert_verifier_builder(
        server_cert_verifier_builder, UnsafePointer.address_of(server_cert_verifier)
    )
    if result != 7000:
        print("failed to build cert store, Result: ", result)
        exit(1)
    
    client_config_builder_set_server_verifier(config_builder, server_cert_verifier)

    # var config_builder = new_client_config_builder()
    var alpn_http11 = String("http/1.1")
    result = client_config_builder_set_alpn_protocols(config_builder, UnsafePointer.address_of(alpn_http11), 1)
    if result != 7000:
        print("failed to set alpn protocol, Result: ", result)
        exit(1)
    
    var client_config = UnsafePointer[ClientConfig]()
    result = build_client_config_builder(config_builder, UnsafePointer.address_of(client_config))
    if result != 7000:
        print("failed to build client config, Result: ", result)
        exit(1)
    
    var host = "www.google.com"
    var port = "443"
    var path = "/"
    try:
        result = do_request(client_config, host, port, path)
        if result != 7000:
            print("failed to build client config, Result: ", result)
            exit(1)
    except e:
        print("Error: ", e)
        exit(1)

    # var client_config = new_client_config()
    # var rconn = UnsafePointer[Connection]()
    # var server: String = "www.google.com"
    # result = new_client_connection(client_config, server.unsafe_ptr(), UnsafePointer.address_of(rconn))
    # if result != 7000:
    #     print("Failed to connect to server, Result: ", result)
    #     exit(1)


#     struct rustls_connection *rconn = NULL;
#   struct conndata *conn = NULL;
#   int ret = 1;
#   int sockfd = make_conn(hostname, port);
#   if(sockfd < 0) {
#     // No perror because make_conn printed error already.
#     goto cleanup;
#   }

#   rustls_result result =
#     rustls_client_connection_new(client_config, hostname, &rconn);
