#ifndef SSLSOCKET_SSL_SOCKET_H
#define SSLSOCKET_SSL_SOCKET_H

#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <schannel.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <Security/SecureTransport.h>
#endif

class ssl_socket {
public:
    ssl_socket(const std::string& host, int port);
    ~ssl_socket();

    bool connect();
    int send(const std::string& data);
    std::string receive();
    void close();

private:
    std::string host_;
    int port_;
    int socket_;

#ifdef _WIN32
    CredHandle hCred_;
    CtxtHandle hCtxt_;
    SecPkgContext_StreamSizes Sizes_;
#else
    SSLContextRef context_;
#endif

    bool create_socket();
    bool perform_handshake();
    void cleanup();
};

#endif //SSLSOCKET_SSL_SOCKET_H
