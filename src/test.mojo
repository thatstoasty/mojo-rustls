import rustls as rls
import os
from utils import StringSlice, Span
from collections import Optional, InlineArray
from memory import Arc

alias DEMO_OK = 0
alias DEMO_AGAIN = 1
alias DEMO_EOF = 2
alias DEMO_ERROR = 3


@value
struct ConnData:
    var fd: Int
    var verify_arg: String
    var data: List[UInt8]


fn do_request(
    client_config: rls.ClientConfig,
    host: String,
    port: String,
    path: String,
) raises:
    # var fd = socket(AF_INET, SOCK_STREAM, 0)
    # var connection = create_connection(fd, host, atol(port))
    # if fd < 0:
    #     print("Failed to create connection")
    #     return ret

    conn = rls.ClientConnection(client_config, host)

    # var conn = ConnData(
    #     rconn, fd.__int__(), "verify_arg", SliceBytes(UnsafePointer[UInt8](), 0)
    # )

    # rustls_connection_set_userdata(
    #     rconn, UnsafePointer[ConnData].address_of(conn)
    # )
    # conn.set_log_callback[log_cb]()

    # send_request_and_read_response(conn, rconn, host, path)


fn log_cb(level: Int, message: StringSlice):
    print("Log level:", level, "Message:", message)


fn send_request_and_read_response(
    #     conn: ConnData,
    conn: rls.ClientConnection,
    hostname: String,
    path: String,
) raises:
    # var sockfd = conn.fd

    # var ret: RustlsResult = 1
    # var result: UInt32 = 1
    # var n: Int = 0
    # var headers_len: Int = 0
    # var content_length: Int = 0
    # var response_complete = False

    headers = (
        "GET "
        + path
        + " HTTP/1.1\r\n"
        + "Host: "
        + hostname
        + "\r\n"
        + "User-Agent: Mojo\r\n"
        + "Accept: carcinization/inevitable, text/html\r\n"
        + "Connection: close\r\n"
        + "\r\n"
    )

    header_bytes = headers.as_bytes_slice()

    # Write plaintext to rustls connection


#     result = rustls_connection_write(
#         rustls_connection, buf.data, len(headers), UnsafePointer.address_of(n)
#     )
#     if result != 7000:
#         print("Error writing plaintext bytes to rustls_connection")
#         return ret
#     if n != len(headers):
#         print("Short write writing plaintext bytes to rustls_connection")
#         return ret

#     var ciphersuite_name = rustls_connection_get_negotiated_ciphersuite_name(
#         rustls_connection
#     )
#     print("Negotiated ciphersuite: ", ciphersuite_name)

#     var read_fds = fd_set()
#     var write_fds = fd_set()

#     while True:
#         read_fds.clear_all()
#         write_fds.clear_all()

#         if rustls_connection_wants_read(rustls_connection):
#             print("Rustls wants read")
#             read_fds.set(sockfd)
#         if rustls_connection_wants_write(rustls_connection):
#             print("Rustls wants write")
#             write_fds.set(sockfd)

#         if not rustls_connection_wants_read(
#             rustls_connection
#         ) and not rustls_connection_wants_write(rustls_connection):
#             print(
#                 "Rustls wants neither read nor write. Drain plaintext and exit"
#             )
#             break

#         var select_result = select(
#             sockfd + 1,
#             UnsafePointer.address_of(read_fds),
#             UnsafePointer.address_of(write_fds),
#             UnsafePointer[fd_set](),
#             UnsafePointer[timeval](),
#         )

#         if select_result == -1:
#             print("Select error: ", select_result)
#             return ret
#         print("Select result:", select_result)
#         print("Read fd set:", read_fds.is_set(sockfd))
#         print("Write fd set:", write_fds.is_set(sockfd))

#         var counter = 0

#         if write_fds.is_set(sockfd):
#             while True:
#                 var conn_ptr = UnsafePointer[ConnData].address_of(conn)
#                 counter += 1
#                 var write_result = rustls_connection_write_tls(
#                     rustls_connection, write_cb, conn_ptr, n
#                 )
#                 if write_result != 7000:
#                     print(
#                         "Error in rustls_connection_write_tls: ", write_result
#                     )
#                     return ret
#                 if write_result == DEMO_AGAIN:
#                     break
#                 elif n == 0:
#                     print("Write returned 0 from rustls_connection_write_tls")
#                     break
#                 if counter > 2:
#                     print("Counter exceeded 10")
#                     break

#         if read_fds.is_set(sockfd) or True:
#             while True:
#                 print("Reading from socket")
#                 var read_result = do_read(conn, rustls_connection)
#                 if read_result == DEMO_AGAIN:
#                     break
#                 elif read_result == DEMO_EOF:
#                     response_complete = True
#                     break
#                 elif read_result != DEMO_OK:
#                     return ret

#                 if headers_len == 0:
#                     var body_start = String(conn.data.data[]).find("\r\n\r\n")
#                     if body_start != -1:
#                         headers_len = body_start
#                         print("Body began at ", headers_len)
#                         var content_length_str = String(conn.data.data[]).find(
#                             "Content-Length: "
#                         )
#                         if content_length_str == -1:
#                             print("Content length header not found")
#                             return ret
#                         content_length = int(
#                             String(conn.data.data[])[content_length_str + 16 :]
#                         )
#                         print("Content length ", content_length)

#                 if (
#                     headers_len != 0
#                     and conn.data.len >= headers_len + content_length
#                 ):
#                     response_complete = True
#                     break

#         if response_complete:
#             break

#     return 7000


# fn write_cb(
#     userdata: UnsafePointer[UInt8],
#     buf: UnsafePointer[UInt8],
#     len: Int,
#     out_n: UnsafePointer[Int],
# ) -> Int:
#     var conn = userdata.bitcast[ConnData]()[]
#     print("Writing to socket, length:", len)
#     print("Record type:", buf[0])
#     print("TLS version:", buf[1], buf[2])
#     print("Length:", (buf[3].__int__() << 8) | buf[4].__int__())
#     if len > 5:
#         print("Handshake type:", buf[5])
#     print("Full data:", buf)
#     var buf_str = buf[].__str__()
#     print("Writing to socket: ", buf_str)
#     var signed_n = send(conn.fd, buf_str.unsafe_ptr(), len, 0)
#     # var signed_n = send(conn.fd, buf, len, 0)
#     if signed_n < 0:
#         print("Error writing to socket, signed_n:", signed_n)
#         return 0
#     out_n[0] = signed_n
#     return 7000


# fn read_cb(
#     userdata: UnsafePointer[UInt8],
#     buf: UnsafePointer[UInt8],
#     len: Int,
#     out_n: UnsafePointer[Int],
# ) -> Int:
#     print("we are in read_cb")
#     var conn = userdata.bitcast[ConnData]()[]
#     print("Reading from socket")
#     var signed_n = read(conn.fd, buf, len)
#     print("signed_n", signed_n)
#     for i in range(signed_n):
#         print(chr(int(buf[i])), end="")
#     print()
#     if signed_n < 0:
#         out_n[0] = 0
#         print("Error reading from socket")
#     out_n[0] = signed_n.__int__()
#     return 0


# fn do_read(conn: ConnData, rconn: UnsafePointer[Connection]) raises -> Int:
#     """
#     Do one read from the socket, process all resulting bytes into the
#     rustls_connection, then copy all plaintext bytes from the session to stdout.
#     Returns:
#      - DEMO_OK for success
#      - DEMO_AGAIN if we got an EAGAIN or EWOULDBLOCK reading from the socket
#      - DEMO_EOF if we got EOF
#      - DEMO_ERROR for other errors.
#     """
#     var err: Int = 1
#     var result: UInt32 = 1
#     var n: Int = 0
#     var n_ptr = UnsafePointer.address_of(n)

#     print("going into rustls_connection_read_tls")
#     err = rustls_connection_read_tls(
#         rconn, read_cb, UnsafePointer.address_of(conn).bitcast[UInt8](), n_ptr
#     )
#     _ = n
#     print("coming out of rustls_connection_read_tls")
#     # if err == EAGAIN or err == EWOULDBLOCK:
#     #     print("Reading from socket: EAGAIN or EWOULDBLOCK: ", err)
#     #     return DEMO_AGAIN
#     # elif err != 0:
#     #     print("Reading from socket: err ", err)
#     #     return DEMO_ERROR

#     result = rustls_connection_process_new_packets(rconn)
#     if result != 7000:
#         print_error("in process_new_packets", result)
#         return DEMO_ERROR

#     # If we got an EOF on the plaintext stream (peer closed connection cleanly),
#     # verify that the sender then closed the TCP connection.
#     var buf = SliceBytes(UnsafePointer[UInt8](), 1)
#     var signed_n = read(conn.fd, buf.data, 1)

#     if signed_n > 0:
#         print(
#             "Error: read returned ",
#             signed_n,
#             " bytes after receiving close_notify",
#         )
#         return DEMO_ERROR
#     elif signed_n < 0:
#         print("Wrong error after receiving close_notify: ", signed_n)
#         return DEMO_ERROR

#     return DEMO_EOF


fn default_provider_with_custom_ciphersuite(
    custom_ciphersuite_name: StringSlice,
) raises -> rls.CryptoProvider:
    custom_ciphersuite = Optional[rls.SupportedCiphersuite]()
    for suite in rls.default_crypto_provider_ciphersuites():
        if not suite:
            raise Error("failed to get ciphersuite")
        if suite.get_name() == custom_ciphersuite_name:
            custom_ciphersuite = suite

    if not custom_ciphersuite:
        raise Error(
            "failed to select custom ciphersuite: "
            + str(custom_ciphersuite_name)
        )

    provider_builder = rls.CryptoProviderBuilder()
    providers = List(custom_ciphersuite.value())
    provider_builder.set_cipher_suites(providers)

    return provider_builder^.build()


fn main() raises:
    var cert_path = "/etc/ssl/cert.pem"
    if not os.setenv("CA_FILE", cert_path):
        raise Error("Failed to set CA_FILE environment variable")

    custom_provider = default_provider_with_custom_ciphersuite(
        "TLS13_CHACHA20_POLY1305_SHA256"
    )
    tls_versions = List[UInt16](0x0303, 0x0304)
    config_builder = rls.ClientConfigBuilder(custom_provider, tls_versions)
    server_cert_root_store_builder = rls.RootCertStoreBuilder()
    server_cert_root_store_builder.load_roots_from_file(cert_path)
    server_root_cert_store = server_cert_root_store_builder^.build()
    server_cert_verifier_builder = rls.WebPkiServerCertVerifierBuilder(
        server_root_cert_store
    )
    server_cert_verifier = server_cert_verifier_builder^.build()
    config_builder.set_server_verifier(server_cert_verifier)
    alpn = List[Span[UInt8, ImmutableAnyLifetime]]("http/1.1".as_bytes_slice())
    config_builder.set_alpn_protocols(alpn)
    client_config = config_builder^.build()
    host = "www.google.com"
    port = "443"
    path = "/"
    # result = do_request(client_config, host, port, path)
