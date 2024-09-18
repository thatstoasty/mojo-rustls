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
    rustls_connection_read_tls,
    rustls_connection_wants_read,
    rustls_connection_wants_write,
    rustls_connection_write_tls,
)
import os
from sys import exit
from memory.memory import memset
from sys.info import sizeof
from sys.ffi import external_call
from lightbug_http.sys.net import create_connection
from libc import fd_set, AF_INET, SOCK_STREAM, AI_PASSIVE, EAGAIN, EWOULDBLOCK, to_char_ptr, socket, select, timeval, read, send

alias DEMO_OK = 0
alias DEMO_AGAIN = 1
alias DEMO_EOF = 2
alias DEMO_ERROR = 3


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
fn send_request_and_read_response(conn: ConnData, rustls_connection: UnsafePointer[Connection], hostname: String, path: String) raises -> RustlsResult:
    var sockfd = conn.fd
    var ret: RustlsResult = 1
    var result: UInt32 = 1
    var n: Int = 0
    var headers_len: Int = 0
    var content_length: Int = 0
    var response_complete = False

    var headers = "GET " + path + " HTTP/1.1\r\n" +
        "Host: " + hostname + "\r\n" +
        "User-Agent: Mojo\r\n" +
        "Accept: carcinization/inevitable, text/html\r\n" +
        "Connection: close\r\n" +
        "\r\n"
    var header_bytes = headers.as_bytes_slice().unsafe_ptr()
    var buf = SliceBytes(header_bytes, len(headers))

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

    var read_fds = fd_set()
    var write_fds = fd_set()

    while True:
        read_fds.clear_all()
        write_fds.clear_all()

        if rustls_connection_wants_read(rustls_connection):
            read_fds.set(sockfd)
        if rustls_connection_wants_write(rustls_connection):
            write_fds.set(sockfd)

        if not rustls_connection_wants_read(rustls_connection) and not rustls_connection_wants_write(rustls_connection):
            print("Rustls wants neither read nor write. Drain plaintext and exit")
            break

        var select_result = select(sockfd + 1, 
                                   UnsafePointer.address_of(read_fds), 
                                   UnsafePointer.address_of(write_fds), 
                                   UnsafePointer[fd_set](), 
                                   UnsafePointer[timeval]())
        
        if select_result == -1:
            print("Select error: ", select_result)
            return ret

        if read_fds.is_set(sockfd):
            while True:
                var read_result = do_read(conn, rustls_connection)
                if read_result == DEMO_AGAIN:
                    break
                elif read_result == DEMO_EOF:
                    response_complete = True
                    break
                elif read_result != DEMO_OK:
                    return ret

                if headers_len == 0:
                    var body_start = String(conn.data.data[]).find("\r\n\r\n")
                    if body_start != -1:
                        headers_len = body_start
                        print("Body began at ", headers_len)
                        var content_length_str = String(conn.data.data[]).find("Content-Length: ")
                        if content_length_str == -1:
                            print("Content length header not found")
                            return ret
                        content_length = int(String(conn.data.data[])[content_length_str + 16:])
                        print("Content length ", content_length)

                if headers_len != 0 and conn.data.len >= headers_len + content_length:
                    response_complete = True
                    break

        if write_fds.is_set(sockfd):
            while True:
                var conn_ptr = UnsafePointer[ConnData].address_of(conn)
                var write_result = rustls_connection_write_tls(rustls_connection, write_cb, conn_ptr, n)
                if write_result != 0:
                    print("Error in rustls_connection_write_tls: ", write_result)
                    return ret
                if write_result == DEMO_AGAIN:
                    break
                elif n == 0:
                    print("Write returned 0 from rustls_connection_write_tls")
                    break

        if response_complete:
            break

    return 7000

fn write_cb(userdata: UnsafePointer[UInt8], buf: UnsafePointer[UInt8], len: Int, out_n: UnsafePointer[Int]) -> Int:
    var conn = userdata.bitcast[ConnData]()[]
    var buf_str = buf[].__str__()
    print("Writing to socket: ", buf_str)
    var signed_n = send(conn.fd, buf_str.unsafe_ptr(), len, 0)
    if signed_n < 0:
        print("Error writing to socket, signed_n: ", signed_n)
        return 1
    out_n[0] = signed_n
    return 0

fn read_cb(userdata: UnsafePointer[UInt8], buf: UnsafePointer[UInt8], len: Int, out_n: UnsafePointer[Int]) -> Int:
    var conn = userdata.bitcast[ConnData]()[]
    var signed_n = read(conn.fd, buf, len)
    print("Read bytes: ", buf)
    if signed_n < 0:
        out_n[0] = 0
        print("Error reading from socket")
    out_n[0] = signed_n.__int__()
    return 0

fn do_read(conn: ConnData, rconn: UnsafePointer[Connection]) raises -> Int:
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
    err = rustls_connection_read_tls(rconn, conn.data.data, conn.data.len, n_ptr)
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

fn print_error(context: String, result: UInt32):
    print("Error in {context}: {rustls_error(result)}")

fn rustls_error(result: UInt32) -> String:
    # Implement this function to return a string representation of the rustls error
    return "Rustls error code: {result}"

fn strerror(err: Int) -> String:
    # Implement this function to return a string representation of the system error
    return "System error code: {err}"


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
