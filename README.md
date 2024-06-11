## Cross-Platform SSLSocket Library

### Overview
The Cross-Platform SSLSocket Library provides a simple way to create secure socket connections using SSL/TLS on both Windows and macOS. This library uses SChannel on Windows and Secure Transport on macOS to handle SSL/TLS connections.

### Features
- Cross-platform support for Windows and macOS
- Secure SSL/TLS connections
- Simple API for connecting, sending, and receiving data

### Usage
1. Include the `ssl-socket.h` and `ssl-socket.cpp` files in your project.
2. Link against the necessary libraries:
   - On Windows, link against `ws2_32.lib` and `secur32.lib`.
   - On macOS, no additional linking is required as Secure Transport is part of the system libraries.

### Class API
#### `SSLSocket`
- **Constructor**: `ssl-socket(const std::string& host, int port)`
  - Initializes a new instance of the `ssl-socket` class.
- **Destructor**: `~ssl-socket()`
  - Cleans up resources.
- **bool connect()**
  - Establishes a secure connection to the specified host and port.
  - Returns `true` if the connection is successful, `false` otherwise.
- **int send(const std::string& data)**
  - Sends data over the secure connection.
  - Returns the number of bytes sent, or `-1` on error.
- **std::string receive()**
  - Receives data from the secure connection.
  - Returns the received data as a string.
- **void close()**
  - Closes the secure connection.

### Implementation Details
- **Windows**: Uses SChannel for SSL/TLS connections.
- **macOS**: Uses Secure Transport for SSL/TLS connections.
