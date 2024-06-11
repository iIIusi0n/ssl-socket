#include <iostream>

#include "ssl-socket.h"

int main() {
    auto socket = ssl_socket(
            "example.com",
            443
            );

    std::clog << "Connecting to example.com" << std::endl;
    if (!socket.connect()) {
        std::cerr << "Failed to connect" << std::endl;
    }
    std::clog << "Connected" << std::endl;

    std::clog << "Sending request" << std::endl;
    auto request = "GET / HTTP/1.1\r\n"
                   "Accept-Encoding: identity\r\n"
                   "Host: example.com\r\n"
                   "Connection: close\r\n"
                   "\r\n";
    socket.send(request);
    std::clog << "Request sent" << std::endl;

    auto response = socket.receive();
    std::cout << "Response length: " << response.length() << std::endl;
    std::cout << response << std::endl;

    return 0;
}
