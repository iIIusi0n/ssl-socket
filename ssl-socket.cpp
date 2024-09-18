#include "ssl-socket.h"

#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <schannel.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <SecureTransport.h>
#endif

ssl_socket::ssl_socket(const std::string& host, int port)
    : host_(host), port_(port), socket_(-1)
#ifdef _WIN32
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
}
#else
{
    context_ = nullptr;
}
#endif

ssl_socket::~ssl_socket() {
    cleanup();
}

bool ssl_socket::create_socket() {
    struct addrinfo hints, *res;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host_.c_str(), std::to_string(port_).c_str(), &hints, &res) != 0) {
        return false;
    }

    socket_ = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (socket_ == -1) {
        freeaddrinfo(res);
        return false;
    }

    if (::connect(socket_, res->ai_addr, res->ai_addrlen) == -1) {
        freeaddrinfo(res);
        close();
        return false;
    }

    freeaddrinfo(res);
    return true;
}

bool ssl_socket::connect() {
    if (!create_socket()) {
        return false;
    }

    return perform_handshake();
}

int ssl_socket::send(const std::string& data) {
#ifdef _WIN32
    return ::send(socket_, data.c_str(), static_cast<int>(data.size()), 0);
#else
    size_t bytes_written;
    OSStatus status = SSLWrite(context_, data.c_str(), static_cast<int>(data.size()), &bytes_written);
    if (status == noErr) {
        return static_cast<int>(bytes_written);
    } else {
        return -1;
    }
#endif
}

std::string ssl_socket::receive() {
    char buffer[4096];
#ifdef _WIN32
    int bytes_received = ::recv(socket_, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        return std::string(buffer, bytes_received);
    } else if (bytes_received == 0) {
        return ""; // Connection closed
    } else {
        // Handle error
        return "";
    }
#else
    size_t bytes_received = 0;
    std::string received_data;
    OSStatus status;

    do {
        status = SSLRead(context_, buffer, sizeof(buffer), &bytes_received);
        if (status == noErr || status == errSSLWouldBlock) {
            if (bytes_received > 0) {
                received_data.append(buffer, bytes_received);
            } else {
                break; // No more data
            }
        } else {
            // Handle error
            return "";
        }
    } while (status == errSSLWouldBlock || bytes_received == sizeof(buffer));

    if (status == noErr || status == errSSLWouldBlock) {
        return received_data;
    } else {
        // Handle error
        return "";
    }
#endif
}

void ssl_socket::close() {
    if (socket_ != -1) {
#ifdef _WIN32
        closesocket(socket_);
#else
        ::close(socket_);
#endif
        socket_ = -1;
    }
}

bool ssl_socket::perform_handshake() {
#ifdef _WIN32
    // Windows-specific SSL/TLS handshake using SChannel
    SCHANNEL_CRED scCred = {0};
    scCred.dwVersion = SCHANNEL_CRED_VERSION;
    scCred.grbitEnabledProtocols = SP_PROT_TLS1_2;

    if (AcquireCredentialsHandle(
            NULL,
            UNISP_NAME,
            SECPKG_CRED_OUTBOUND,
            NULL,
            &scCred,
            NULL,
            NULL,
            &hCred_,
            NULL) != SEC_E_OK) {
        return false;
    }

    SecBufferDesc OutBuffer;
    SecBuffer OutSecBuffer[1];
    SecBufferDesc InBuffer;
    SecBuffer InSecBuffer[1];

    DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
                         ISC_REQ_REPLAY_DETECT |
                         ISC_REQ_CONFIDENTIALITY |
                         ISC_REQ_EXTENDED_ERROR |
                         ISC_REQ_ALLOCATE_MEMORY |
                         ISC_REQ_STREAM;

    DWORD dwSSPIOutFlags;
    ULONG ulContextAttr;
    TimeStamp tsExpiry;
    SECURITY_STATUS scRet;
    DWORD cbIoBuffer = 0;
    BOOL fDoRead = TRUE;
    PBYTE pbIoBuffer = (PBYTE)LocalAlloc(LMEM_FIXED, 0x10000);
    if (!pbIoBuffer) {
        return false;
    }

    scRet = SEC_I_CONTINUE_NEEDED;
    while (scRet == SEC_I_CONTINUE_NEEDED ||
           scRet == SEC_E_INCOMPLETE_MESSAGE ||
           scRet == SEC_I_INCOMPLETE_CREDENTIALS) {
        if (cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE) {
            if (fDoRead) {
                int cbData = recv(socket_, (char*)pbIoBuffer + cbIoBuffer, 0x10000 - cbIoBuffer, 0);
                if (cbData == SOCKET_ERROR) {
                    scRet = WSAGetLastError();
                    break;
                } else if (cbData == 0) {
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                cbIoBuffer += cbData;
            } else {
                fDoRead = TRUE;
            }
        }

        InSecBuffer[0].pvBuffer = pbIoBuffer;
        InSecBuffer[0].cbBuffer = cbIoBuffer;
        InSecBuffer[0].BufferType = SECBUFFER_TOKEN;
        InBuffer.cBuffers = 1;
        InBuffer.pBuffers = InSecBuffer;
        InBuffer.ulVersion = SECBUFFER_VERSION;

        OutSecBuffer[0].pvBuffer = NULL;
        OutSecBuffer[0].BufferType = SECBUFFER_TOKEN;
        OutSecBuffer[0].cbBuffer = 0;
        OutBuffer.cBuffers = 1;
        OutBuffer.pBuffers = OutSecBuffer;
        OutBuffer.ulVersion = SECBUFFER_VERSION;

        scRet = InitializeSecurityContext(
            &hCred_,
            NULL,
            (SEC_CHAR*)host_.c_str(),
            dwSSPIFlags,
            0,
            SECURITY_NATIVE_DREP,
            &InBuffer,
            0,
            &hCtxt_,
            &OutBuffer,
            &dwSSPIOutFlags,
            &tsExpiry);

        if (scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED ||
            (FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))) {
            if (OutSecBuffer[0].cbBuffer != 0 && OutSecBuffer[0].pvBuffer != NULL) {
                int cbData = send(socket_, (char*)OutSecBuffer[0].pvBuffer, OutSecBuffer[0].cbBuffer, 0);
                if (cbData == SOCKET_ERROR || cbData == 0) {
                    scRet = WSAGetLastError();
                    FreeContextBuffer(OutSecBuffer[0].pvBuffer);
                    break;
                }
                FreeContextBuffer(OutSecBuffer[0].pvBuffer);
            }

            if (scRet == SEC_E_INCOMPLETE_MESSAGE) {
                fDoRead = FALSE;
                continue;
            }

            if (scRet == SEC_I_CONTINUE_NEEDED || scRet == SEC_E_OK) {
                if (InSecBuffer[0].BufferType == SECBUFFER_EXTRA) {
                    memmove(pbIoBuffer, (PBYTE)pbIoBuffer + (cbIoBuffer - InSecBuffer[0].cbBuffer), InSecBuffer[0].cbBuffer);
                    cbIoBuffer = InSecBuffer[0].cbBuffer;
                } else {
                    cbIoBuffer = 0;
                }
            }
        } else {
            FreeContextBuffer(pbIoBuffer);
            DeleteSecurityContext(&hCtxt_);
            return false;
        }
    }

    FreeContextBuffer(pbIoBuffer);
    if (FAILED(scRet)) {
        DeleteSecurityContext(&hCtxt_);
        return false;
    }

    return true;
#else
    // macOS-specific SSL/TLS handshake using SecureTransport
    context_ = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    if (!context_) {
        return false;
    }

    SSLSetIOFuncs(context_,
                 [](SSLConnectionRef connection, void *data, size_t *dataLength) -> OSStatus {
                     int socket = static_cast<int>(reinterpret_cast<intptr_t>(connection));
                     ssize_t result = ::read(socket, data, *dataLength);
                     if (result > 0) {
                         *dataLength = result;
                         return noErr;
                     }
                     return result == 0 ? errSSLClosedGraceful : errSSLClosedAbort;
                 },
                 [](SSLConnectionRef connection, const void *data, size_t *dataLength) -> OSStatus {
                     int socket = static_cast<int>(reinterpret_cast<intptr_t>(connection));
                     ssize_t result = ::write(socket, data, *dataLength);
                     if (result > 0) {
                         *dataLength = result;
                         return noErr;
                     }
                     return result == 0 ? errSSLClosedGraceful : errSSLClosedAbort;
                 });

    SSLSetConnection(context_, reinterpret_cast<SSLConnectionRef>(static_cast<intptr_t>(socket_)));
    SSLSetPeerDomainName(context_, host_.c_str(), static_cast<UInt32>(host_.length()));
    OSStatus status = SSLHandshake(context_);
    if (status != noErr) {
        std::cerr << "SSLHandshake error: " << status << std::endl;
        SSLDisposeContext(context_);
        context_ = nullptr;
        return false;
    }

    return true;
#endif
}

void ssl_socket::cleanup() {
    close();
#ifdef _WIN32
    FreeCredentialsHandle(&hCred_);
    DeleteSecurityContext(&hCtxt_);
#else
    if (context_) {
        CFRelease(context_);
        context_ = nullptr;
    }
#endif
}
