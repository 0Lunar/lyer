# Lyer

## Description

Lyer is a Python library designed to securely transfer files between a client and server using sockets and AES-GCM encryption. Lyer follows an FTP-like protocol but with custom rules to provide enhanced security and control over data transfers. The library currently supports user authentication, directory content listing, and file transfers.

**status**: The library is currently under development (beta).

**Key Features**:

- **Authentication**: Includes an integrated class that interacts with a MySQL database to handle user authentication using the auth table.
- **Directory content listing**: Clients can request a list of files from a specific directory on the server.
- **File transfer**: Supports sending and receiving files. Lyer uses AES-GCM to ensure that transferred files are secure during transmission.

*Note*: Data reception is handled by the user through sockets. Lyer processes and decrypts received packets, returning the decrypted data.

## Requirements

- **Python**: Version 3.10 or higher
- **Required libraries**:
    - `pycryptodome`: For AES-GCM encryption
    - `mysql-connector-python`: For MySQL database connection


## Current Functionality:

1. Authentication:
    - Authentication is managed through direct interaction with a MySQL database, where usernames and passwords are stored as hashed values.
    - The authentication class supports sending credentials and verifying them through the `auth` table.

2. Directory content listing:
    - A feature that allows clients to request and receive a list of files in a specified server directory.

3. File transfer:
    - Send file: The client can send a file to the server using sockets.
    - Receive file: The user can receive a file through sockets. Lyer handles packet processing and decryption.


## Example


**CLIENT**

```python
from lyer import LyerDirInfo, Connection, LyerSec
import socket


# Connect to the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8080))
conn = Connection(s, ("127.0.0.1", 8080))


# Get directory info
password = LyerSec.hashPassword(b"Encryption password")
dirInfo = LyerDirInfo(password, conn)
dirs = dirInfo.get("/etc")


# Print all the directory
for i in dirs:
    i = i.decode()
    if i[0] == "D":
        print("<DIR>  " + i)
    
    else:
        print("<FILE> " + i)
```


**SERVER**

```python
from lyer import LyerDirInfo, LyerReciver, LyerSec
import struct


# Create a server
reciver = LyerReciver("127.0.0.1", 8080)
reciver.initServer()

# Accept new connection
conn = reciver.accept()


# recive the message from the client
data = conn.recv(1024)[4:]  #[4:] because we need to exclude the prefix

while struct.pack(">i", 0) not in data:
    data += conn.recv(1024)

data = struct.pack(">i", 0) + data

# send directory info
password = LyerSec.hashPassword(b"Encryption password")
dirInfo = LyerDirInfo(password, conn)
directory = dirInfo.disasGet(data)
dirInfo.send(directory.decode())
```