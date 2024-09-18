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
    rustls_connection_write,
    rustls_connection_get_negotiated_ciphersuite,
    rustls_connection_get_negotiated_ciphersuite_name
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
    if result != 7000:
        print("failed to create new client connection, Result: ", result)
        return result

    var conn = ConnData(rconn, fd.__int__(), "verify_arg", SliceBytes(UnsafePointer[UInt8](), 0))

    rustls_connection_set_userdata(rconn, UnsafePointer[ConnData].address_of(conn))
    # rustls_connection_set_log_callback(rconn, log_cb)

    ret = send_request_and_read_response(conn, rconn, host, path)
    if ret != 7000:
        return ret
    
    return 7000 

fn log_cb(level: Int, message: String):
    print("Log level:", level, "Message:", message)

@value
struct FdSet:
    var fds: List[Int]
    fn clear(inout self):
        self.fds = List[Int]()
    fn set(inout self, fd: Int):
        self.fds.append(fd)
    fn is_set(inout self, fd: Int) -> Bool:
        return fd in self.fds
    fn address(inout self) -> UnsafePointer[Int]:
        return self.fds.unsafe_ptr()

# fn send_request_and_read_response(conn: UnsafePointer[ConnData], rustls_connection: UnsafePointer[Connection], hostname: String, path: String) -> RustlsResult:
fn send_request_and_read_response(conn: ConnData, rustls_connection: UnsafePointer[Connection], hostname: String, path: String) raises -> RustlsResult:
    var sockfd = conn.fd
    var ret: RustlsResult = 1
    var err = 1
    var result: UInt32 = 1
    var buf = SliceBytes(UnsafePointer[UInt8](), 0)
    var read_fds = FdSet(List[Int]())
    var write_fds = FdSet(List[Int]())
    var n: Int = 0
    var body: String = ""
    var content_length: Int = 0
    var headers_len: Int = 0

    # var version = rustls_version()
    var headers = '''GET {path} HTTP/1.1\r\n
        Host: {hostname}\r\n
        User-Agent: {version}\r\n
        Accept: carcinization/inevitable, text/html\r\n
        Connection: close\r\n
        \r\n'''
    var header_bytes = headers.as_bytes_slice().unsafe_ptr()
    buf = SliceBytes(header_bytes, len(headers))

    # Write plaintext to rustls connection
    result = rustls_connection_write(rustls_connection, buf.as_bytes(), buf.length(), n.address())
    if result != 7000:
        print("Error writing plaintext bytes to rustls_connection")
        return ret
    if n != len(headers):
        print("Short write writing plaintext bytes to rustls_connection")
        return ret

    var ciphersuite_id = rustls_connection_get_negotiated_ciphersuite(rustls_connection)
    var ciphersuite_name = rustls_connection_get_negotiated_ciphersuite_name(rustls_connection)
    print("Negotiated ciphersuite: ", ciphersuite_name)

    while True:
        read_fds.clear()
        write_fds.clear()

        if rustls_connection_wats_read(rustls_connection):
            read_fds.set(sockfd)
        if rustls_connection_wants_write(rustls_connection):
            write_fds.set(sockfd)

        if not rustls_connection_wants_read(rustls_connection) and not rustls_connection_wants_write(rustls_connection):
            print("Rustls wants neither read nor write. Drain plaintext and exit")
            break

        let select_result = select(sockfd + 1, read_fds.address(), write_fds.address(), None, None)
        if select_result == -1:
            print("Client: select error")
            return ret

        if read_fds.is_set(sockfd):
            while True:
                result = do_read(conn, rustls_connection)
                if result == DEMO_AGAIN:
                    break
                elif result == DEMO_EOF:
                    return drain_plaintext(conn)
                elif result != DEMO_OK:
                    return ret

                if headers_len == 0:
                    body = body_beginning(conn.data)
                    if body:
                        headers_len = body.length()
                        print(f"Body began at {headers_len}")
                        content_length_str = get_first_header_value(conn.data.data, headers_len, "Content-Length")
                        if not content_length_str:
                            print("Content length header not found")
                            return ret
                        content_length = int(content_length_str)
                        print(f"Content length {content_length}")

                if headers_len != 0 and conn.data.len >= headers_len + content_length:
                    return drain_plaintext(conn)

        if write_fds.is_set(sockfd):
            while True:
                err = write_tls(rustls_connection, conn, n.address())
                if err != 0:
                    print(f"Error in rustls_connection_write_tls: errno {err}")
                    return ret
                if result == DEMO_AGAIN:
                    break
                elif n == 0:
                    print("Write returned 0 from rustls_connection_write_tls")
                    break

    print("Send_request_and_read_response: loop fell through")
    return ret

fn drain_plaintext(conn: UnsafePointer[ConnData]) raises -> RustlsResult:
    let result = copy_plaintext_to_buffer(conn)
    if result != DEMO_OK and result != DEMO_EOF:
        return 1
    print(f"Writing {conn.data.len} bytes to stdout")
    # Note: In Mojo, you might need to use a different method to write to stdout
    # This is a placeholder and might need to be adjusted
    print(conn.data.data.decode())
    return 0

# {
#   int sockfd = conn->fd;
#   int ret = 1;
#   int err = 1;
#   unsigned result = 1;
#   char buf[2048];
#   fd_set read_fds;
#   fd_set write_fds;
#   size_t n = 0;
#   const char *body;
#   const char *content_length_str;
#   const char *content_length_end;
#   unsigned long content_length = 0;
#   size_t headers_len = 0;
#   struct rustls_str version;
#   int ciphersuite_id;
#   struct rustls_str ciphersuite_name;

#   version = rustls_version();
#   memset(buf, '\0', sizeof(buf));
#   snprintf(buf,
#            sizeof(buf),
#            "GET %s HTTP/1.1\r\n"
#            "Host: %s\r\n"
#            "User-Agent: %.*s\r\n"
#            "Accept: carcinization/inevitable, text/html\r\n"
#            "Connection: close\r\n"
#            "\r\n",
#            path,
#            hostname,
#            (int)version.len,
#            version.data);
#   /* First we write the plaintext - the data that we want rustls to encrypt for
#    * us- to the rustls connection. */
#   result = rustls_connection_write(rconn, (uint8_t *)buf, strlen(buf), &n);
#   if(result != RUSTLS_RESULT_OK) {
#     LOG_SIMPLE("error writing plaintext bytes to rustls_connection");
#     goto cleanup;
#   }
#   if(n != strlen(buf)) {
#     LOG_SIMPLE("short write writing plaintext bytes to rustls_connection");
#     goto cleanup;
#   }

#   ciphersuite_id = rustls_connection_get_negotiated_ciphersuite(rconn);
#   ciphersuite_name = rustls_connection_get_negotiated_ciphersuite_name(rconn);
#   LOG("negotiated ciphersuite: %.*s (%#x)",
#       (int)ciphersuite_name.len,
#       ciphersuite_name.data,
#       ciphersuite_id);

#   for(;;) {
#     FD_ZERO(&read_fds);
#     /* These two calls just inspect the state of the connection - if it's time
#     for us to write more, or to read more. */
#     if(rustls_connection_wants_read(rconn)) {
#       FD_SET(sockfd, &read_fds);
#     }
#     FD_ZERO(&write_fds);
#     if(rustls_connection_wants_write(rconn)) {
#       FD_SET(sockfd, &write_fds);
#     }

#     if(!rustls_connection_wants_read(rconn) &&
#        !rustls_connection_wants_write(rconn)) {
#       LOG_SIMPLE(
#         "rustls wants neither read nor write. drain plaintext and exit");
#       goto drain_plaintext;
#     }

#     int select_result = select(sockfd + 1, &read_fds, &write_fds, NULL, NULL);
#     if(select_result == -1) {
#       perror("client: select");
#       goto cleanup;
#     }

#     if(FD_ISSET(sockfd, &read_fds)) {
#       /* Read all bytes until we get EAGAIN. Then loop again to wind up in
#          select awaiting the next bit of data. */
#       for(;;) {
#         result = do_read(conn, rconn);
#         if(result == DEMO_AGAIN) {
#           break;
#         }
#         else if(result == DEMO_EOF) {
#           goto drain_plaintext;
#         }
#         else if(result != DEMO_OK) {
#           goto cleanup;
#         }
#         if(headers_len == 0) {
#           body = body_beginning(&conn->data);
#           if(body != NULL) {
#             headers_len = body - conn->data.data;
#             LOG("body began at %zu", headers_len);
#             content_length_str = get_first_header_value(conn->data.data,
#                                                         headers_len,
#                                                         CONTENT_LENGTH,
#                                                         strlen(CONTENT_LENGTH),
#                                                         &n);
#             if(content_length_str == NULL) {
#               LOG_SIMPLE("content length header not found");
#               goto cleanup;
#             }
#             content_length =
#               strtoul(content_length_str, (char **)&content_length_end, 10);
#             if(content_length_end == content_length_str) {
#               LOG("invalid Content-Length '%.*s'", (int)n, content_length_str);
#               goto cleanup;
#             }
#             LOG("content length %lu", content_length);
#           }
#         }
#         if(headers_len != 0 &&
#            conn->data.len >= headers_len + content_length) {
#           goto drain_plaintext;
#         }
#       }
#     }
#     if(FD_ISSET(sockfd, &write_fds)) {
#       for(;;) {
#         /* This invokes rustls_connection_write_tls. We pass a callback to
#          * that function. Rustls will pass a buffer to that callback with
#          * encrypted bytes, that we will write to `conn`. */
#         err = write_tls(rconn, conn, &n);
#         if(err != 0) {
#           LOG("error in rustls_connection_write_tls: errno %d", err);
#           goto cleanup;
#         }
#         if(result == DEMO_AGAIN) {
#           break;
#         }
#         else if(n == 0) {
#           LOG_SIMPLE("write returned 0 from rustls_connection_write_tls");
#           break;
#         }
#       }
#     }
#   }

#   LOG_SIMPLE("send_request_and_read_response: loop fell through");

# drain_plaintext:
#   result = copy_plaintext_to_buffer(conn);
#   if(result != DEMO_OK && result != DEMO_EOF) {
#     goto cleanup;
#   }
#   LOG("writing %zu bytes to stdout", conn->data.len);
#   if(write(STDOUT_FILENO, conn->data.data, conn->data.len) < 0) {
#     LOG_SIMPLE("error writing to stderr");
#     goto cleanup;
#   }
#   ret = 0;

# cleanup:
#   if(sockfd > 0) {
#     close(sockfd);
#   }
#   return ret;
# }



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
