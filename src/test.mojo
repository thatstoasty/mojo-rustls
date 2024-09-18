from rustls import (
    _rustls,
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
    rustls_connection_get_negotiated_ciphersuite_name,
    # rustls_connection_read_tls,
)
import os
from sys import exit
from memory.memory import memset
from sys.info import sizeof
from sys.ffi import external_call
from lightbug_http.sys.net import create_connection
from libc import fd_set, AF_INET, SOCK_STREAM, AI_PASSIVE, EAGAIN, EWOULDBLOCK, to_char_ptr, socket, select, timeval, read

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

# fn send_request_and_read_response(conn: UnsafePointer[ConnData], rustls_connection: UnsafePointer[Connection], hostname: String, path: String) -> RustlsResult:
# fn send_request_and_read_response(conn: ConnData, rustls_connection: UnsafePointer[Connection], hostname: String, path: String) raises -> RustlsResult:
#     var sockfd = conn.fd
#     var ret: RustlsResult = 1
#     var err = 1
#     var result: UInt32 = 1
#     var buf = SliceBytes(UnsafePointer[UInt8](), 0)
#     var read_fds = fd_set()
#     var write_fds = fd_set()
#     var n: Int = 0
#     var body: String = ""
#     var content_length: Int = 0
#     var headers_len: Int = 0

#     # var version = rustls_version()
#     var headers = '''GET {path} HTTP/1.1\r\n
#         Host: {hostname}\r\n
#         User-Agent: {version}\r\n
#         Accept: carcinization/inevitable, text/html\r\n
#         Connection: close\r\n
#         \r\n'''
#     var header_bytes = headers.as_bytes_slice().unsafe_ptr()
#     buf = SliceBytes(header_bytes, len(headers))

#     # Write plaintext to rustls connection
#     result = rustls_connection_write(rustls_connection, buf.data, len(headers), UnsafePointer.address_of(n))
#     if result != 7000:
#         print("Error writing plaintext bytes to rustls_connection")
#         return ret
#     if n != len(headers):
#         print("Short write writing plaintext bytes to rustls_connection")
#         return ret

#     var ciphersuite_id = rustls_connection_get_negotiated_ciphersuite(rustls_connection)
#     var ciphersuite_name = rustls_connection_get_negotiated_ciphersuite_name(rustls_connection)
#     print("Negotiated ciphersuite: ", ciphersuite_name)
#     while True:
#         # read_fds.clear()
#         # write_fds.clear()
#         read_fds.set(sockfd)
#         write_fds.set(sockfd)
        
#         var timeout = timeval(5, 0)  # 5 seconds timeout
#         var select_result = select(sockfd + 1, read_fds_ptr, write_fds_ptr, fd_set_ptr, UnsafePointer.address_of(timeout))
        
#         if select_result == -1:
#             print("Select error: ", errno())
#             break
#         elif select_result == 0:
#             print("Select timeout")
#             continue
        
#         if read_fds.is_set(sockfd):
#             # Perform read operation
#             # Break if all data has been read
        
#         if write_fds.is_set(sockfd):
#             # Perform write operation
#             # Break if all data has been written
        
#         # Add a condition to break the loop when all operations are complete
#         if all_operations_complete:
#             break

#     # while True:
#     #     read_fds.clear(sockfd)
#     #     write_fds.clear(sockfd)
        
#     #     var read_fds_ptr = UnsafePointer[fd_set].address_of(read_fds)
#     #     var write_fds_ptr = UnsafePointer[fd_set].address_of(write_fds)

#     #     print("going into select")
#     #     var fd_set_ptr = UnsafePointer[fd_set]()
#     #     var timeval_ptr = UnsafePointer[timeval]()
#     #     var select_result = select(sockfd + 1, read_fds_ptr, write_fds_ptr, fd_set_ptr, timeval_ptr)
#     #     print("select result: ", select_result)
#     #     if select_result == -1:
#     #         print("Client: select error")
#     #         return ret

#     #     if read_fds.is_set(sockfd):
#     #         while True:
#     #             var conn_ptr = UnsafePointer[ConnData].address_of(conn)
#     #             print("Reading from socket")
#     #             result = do_read(conn_ptr, rustls_connection)
#     #             if result == DEMO_AGAIN:
#     #                 break
#     #             elif result == DEMO_EOF:
#     #                 return 0 # drain_plaintext
#     #             elif result != DEMO_OK:
#     #                 return ret









#                 # if headers_len == 0:
#                 #     body = body_beginning(conn.data)
#                 #     if body:
#                 #         headers_len = body.length()
#                 #         print(f"Body began at {headers_len}")
#                 #         content_length_str = get_first_header_value(conn.data.data, headers_len, "Content-Length")
#                 #         if not content_length_str:
#                 #             print("Content length header not found")
#                 #             return ret
#                 #         content_length = int(content_length_str)
#                 #         print(f"Content length {content_length}")

#                 # if headers_len != 0 and conn.data.len >= headers_len + content_length:
#                 #     return drain_plaintext(conn)

#         # if write_fds.is_set(sockfd):
#         #     while True:
#         #         err = write_tls(rustls_connection, conn, n.address())
#         #         if err != 0:
#         #             print(f"Error in rustls_connection_write_tls: errno {err}")
#         #             return ret
#         #         if result == DEMO_AGAIN:
#         #             break
#         #         elif n == 0:
#         #             print("Write returned 0 from rustls_connection_write_tls")
#         #             break

#     print("Send_request_and_read_response: loop fell through")
#     return ret
fn send_request_and_read_response(conn: ConnData, rustls_connection: UnsafePointer[Connection], hostname: String, path: String) raises -> RustlsResult:
    var sockfd = conn.fd
    var ret: RustlsResult = 1
    var result: UInt32 = 1
    var buf = SliceBytes(UnsafePointer[UInt8](), 0)
    var read_fds = fd_set()
    var write_fds = fd_set()
    var n: Int = 0

    # Prepare the HTTP request
    var headers = '''GET {path} HTTP/1.1\r\n
        Host: {hostname}\r\n
        User-Agent: Mojo/1.0\r\n
        Accept: text/html\r\n
        Connection: close\r\n
        \r\n'''
    var header_bytes = headers.as_bytes_slice().unsafe_ptr()
    buf = SliceBytes(header_bytes, len(headers))

    # Write plaintext to rustls connection
    result = rustls_connection_write(rustls_connection, buf.data, len(headers), UnsafePointer.address_of(n))
    if result != 7000:
        print("Error writing plaintext bytes to rustls_connection")
        return ret
    if n != len(headers):
        print("Short write writing plaintext bytes to rustls_connection")
        return ret

    var ciphersuite_name = rustls_connection_get_negotiated_ciphersuite_name(rustls_connection)
    print("Negotiated ciphersuite: ", ciphersuite_name)

    while True:
        # read_fds.clear()
        # write_fds.clear()
        read_fds.set(sockfd)
        write_fds.set(sockfd)
        
        var timeout = timeval(5, 0)  # 5 seconds timeout
        
        print("Going into select")
        var select_result = select(sockfd + 1, 
                                   UnsafePointer.address_of(read_fds), 
                                   UnsafePointer.address_of(write_fds), 
                                   UnsafePointer[fd_set](), 
                                   UnsafePointer.address_of(timeout))
        print("Select result: ", select_result)
        
        if select_result == -1:
            print("Select error: ", select_result)
            break
        elif select_result == 0:
            print("Select timeout")
            continue
        
        if read_fds.is_set(sockfd):
            # Perform read operation
            var read_buf = SliceBytes(UnsafePointer[UInt8](), 4096)  # Adjust buffer size as needed
            var conn_ptr = UnsafePointer[ConnData].address_of(conn)
            var bytes_read = rustls_connection_read_tls(rustls_connection, conn_ptr)
            if bytes_read == 7000:  # RUSTLS_RESULT_OK
                if n > 0:
                    print("Read ", n, " bytes")
                    # Process the read data here
                else:
                    print("No data read, connection might be closed")
                    break
            elif bytes_read == 7001:  # RUSTLS_RESULT_WOULD_BLOCK
                continue
            else:
                print("Error reading from connection")
                break
        
        if write_fds.is_set(sockfd):
            # Perform write operation if needed
            # For now, we'll assume all data was written in the initial request
            pass
        
        # Add a condition to break the loop when all operations are complete
        # For example, if you've received a complete HTTP response
        # if response_complete:
        #     break

    return 7000  # RUSTLS_RESULT_OK



alias DEMO_OK = 0
alias DEMO_AGAIN = 1
alias DEMO_EOF = 2
alias DEMO_ERROR = 3

alias ReadCallback = fn(UnsafePointer[UInt8], UnsafePointer[UInt8], Int, UnsafePointer[Int]) -> Int

fn read_cb(userdata: UnsafePointer[UInt8], buf: UnsafePointer[UInt8], len: Int, out_n: UnsafePointer[Int]) -> Int:
    var conn = userdata.bitcast[ConnData]()[]
    var signed_n = read(conn.fd, buf, len)
    print("Read bytes: ", buf)
    if signed_n < 0:
        # out_n.store(0)
        print("Error reading from socket")
        # return errno()
    # out_n.store(signed_n)
    return 0

fn rustls_connection_read_tls(rconn: UnsafePointer[Connection], conn: UnsafePointer[ConnData]) raises -> Int:
    var n: Int = 0
    print("We are in rustls_connection_read_tls")
    var result = _rustls.get_function[
        fn(UnsafePointer[Connection], ReadCallback, UnsafePointer[ConnData], UnsafePointer[Int]) -> Int
    ]("rustls_connection_read_tls")(rconn, read_cb, conn, UnsafePointer.address_of(n))
    return result

fn do_read(conn: UnsafePointer[ConnData], rconn: UnsafePointer[Connection]) raises -> Int:
    """
    Do one read from the socket, process all resulting bytes into the
    rustls_connection, then copy all plaintext bytes from the session to stdout.
    Returns:
     - DEMO_OK for success
     - DEMO_AGAIN if we got an EAGAIN or EWOULDBLOCK reading from the socket
     - DEMO_EOF if we got EOF
     - DEMO_ERROR for other errors.
    """
    var err: Int = 1
    var result: UInt32 = 1
    var n: Int = 0
    var n_ptr = UnsafePointer.address_of(n)
    
    print("going into rustls_connection_read_tls")
    err = rustls_connection_read_tls(rconn, conn)
    print("coming out of rustls_connection_read_tls")
    if err == EAGAIN or err == EWOULDBLOCK:
        print("Reading from socket: EAGAIN or EWOULDBLOCK: {strerror(errno())}")
        return DEMO_AGAIN
    elif err != 0:
        print("Reading from socket: errno {err}")
        return DEMO_ERROR

    # result = rustls_connection_process_new_packets(rconn)
    # if result != 7000:
    #     print_error("in process_new_packets", result)
    #     return DEMO_ERROR

    # result = copy_plaintext_to_buffer(conn)
    # if result != DEMO_EOF:
    #     return result

    # If we got an EOF on the plaintext stream (peer closed connection cleanly),
    # verify that the sender then closed the TCP connection.
    # var buf = Bytes(1)
    # let signed_n = read(conn.fd, buf.data(), 1)
    
    # if signed_n > 0:
    #     print(f"Error: read returned {signed_n} bytes after receiving close_notify")
    #     return DEMO_ERROR
    # elif signed_n < 0 and errno() != EWOULDBLOCK:
    #     print(f"Wrong error after receiving close_notify: {strerror(errno())}")
    #     return DEMO_ERROR
    
    return DEMO_EOF

# fn read_cb(userdata: UnsafePointer[UInt8], buf: UnsafePointer[UInt8], len: Int, out_n: UnsafePointer[Int]) -> Int:
#     let conn = userdata.bitcast[ConnData]()
#     let signed_n = read(conn.fd, buf, len)
#     if signed_n < 0:
#         out_n.store(0)
#         return errno()
#     out_n.store(signed_n)
#     return 0

fn print_error(context: String, result: UInt32):
    print("Error in {context}: {rustls_error(result)}")

fn rustls_error(result: UInt32) -> String:
    # Implement this function to return a string representation of the rustls error
    # You might need to use the rustls API to get the error string
    return "Rustls error code: {result}"

fn strerror(err: Int) -> String:
    # Implement this function to return a string representation of the system error
    # You might need to use a system API or a lookup table
    return "System error code: {err}"

# fn drain_plaintext(conn: UnsafePointer[ConnData]) raises -> RustlsResult:
#     var result = copy_plaintext_to_buffer(conn)
#     if result != DEMO_OK and result != DEMO_EOF:
#         return 1
#     print(f"Writing {conn.data.len} bytes to stdout")
#     print(conn.data.data.decode())
#     return 0

# fn copy_plaintext_to_buffer(conn: UnsafePointer[ConnData]) raises -> RustlsResult:
#     var buf = String()
#     var total_read: Int = 0
    
#     while True:
#         var n: Int = 0
#         var result = rustls_connection_read(conn.rconn, buf.as_bytes(), buf.length(), n.address())
        
#         if result == 7000:
#             if n > 0:
#                 conn.data.append(buf[:n])
#                 total_read += n
#             else:
#                 break  # No more data to read
#         elif result == RUSTLS_RESULT_WOULD_BLOCK:
#             break  # Would block, try again later
#         else:
#             return result  # Error occurred
    
#     return RUSTLS_RESULT_OK

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
