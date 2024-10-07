import struct
from .checker import LyerChecker
from .security import LyerSec, LyerPacketAuth
from .reciver import Connection
import hashlib
import os


COMMAND_SIZE = 2
PREFIX_SIZE = 4
SHA256_SIZE = 32
MD5_SIZE = 16


"""
COMMANDS:

0: Authenticate
1. Get directory info
2. Send File
"""


class LyerCommand:
    def get(packet: bytes) -> int | None:
        if LyerChecker.checkPacket(packet):
            packet = packet[PREFIX_SIZE : PREFIX_SIZE + COMMAND_SIZE]
            return int.from_bytes(packet)

        return None


class LyerDirInfo:
    """ Get directory info
    
    prefix: 4-bytes = \x00\x00\x00\x00
    command: 2-bytes = \x00\x01
    directory: x-bytes  -> nonce, data, tag
    integrity-hash: 16-bytes
    end-prefix: 4-bytes = \x00\x00\x00\x00
    """

    def __init__(self, password: bytes, conn: Connection) -> None:
        if type(conn) == Connection and type(password) == bytes and LyerChecker.isDigSha256(password):
            self.conn = conn
            self.password = password
        
        else:
            raise ValueError("Invalid arguments - password = sha256; conn = Connection")

    
    def get(self, directory: str):
        encrypted = LyerSec.encryptData(directory.encode(), self.password)
        encrypted = encrypted[0] + encrypted[1] + encrypted[2]
        data_len = len(encrypted)

        packet = bytearray(26 + data_len)
        packet[0 : PREFIX_SIZE] = struct.pack(">i", 0)      #\x00\x00\x00\x00 -> prefix
        packet[PREFIX_SIZE : PREFIX_SIZE + COMMAND_SIZE] = struct.pack(">h", 1)     #\x00\x01 -> command 
        packet[PREFIX_SIZE + COMMAND_SIZE : PREFIX_SIZE + COMMAND_SIZE + data_len] = encrypted  # encrypted packet
        packet[PREFIX_SIZE + COMMAND_SIZE + data_len : PREFIX_SIZE + COMMAND_SIZE + data_len + MD5_SIZE] = hashlib.md5(encrypted).digest()      # hash to verify packet integrity
        packet[PREFIX_SIZE + COMMAND_SIZE + data_len + MD5_SIZE : ] = struct.pack(">i", 0)  # \x00\x00\x00\x00 -> end

        packet = packet[:PREFIX_SIZE] + packet[PREFIX_SIZE : -PREFIX_SIZE].replace(b"\x00\x00\x00\x00", b"\xff\x00\x00\x00\x00") + packet[-PREFIX_SIZE:]

        packet = bytes(packet)

        self.conn.send(packet)
        data = self.conn.recv(1024)[4:]
        
        while struct.pack(">i", 0) not in data:
            data += self.conn.recv(1024)

        data = struct.pack(">i", 0) + data


        data = data.replace(b"\xff\x00\x00\x00\x00", b"\x00\x00\x00\x00")
        data = data[PREFIX_SIZE : -PREFIX_SIZE]  #exclude the prefix
        
        if hashlib.md5(data[: -MD5_SIZE]).digest() == data[ -MD5_SIZE :]:
            data = data[: -MD5_SIZE]

            if data != b'\x00':         #if the data is \x00 mean that the directory doesn't exist
                nonce = data[: 16]
                encrypted_data = data[16 : -16]
                tag = data[len(data) - 16 :]

                decrypted_data = LyerSec.decryptData(encrypted_data, self.password, nonce, tag)

                return decrypted_data.split(b"\x99")[:-1]
            
            else:
                return None
    
        else:
            raise RuntimeError("Data integrity check failed")
        
    
    def send(self, directory: str) -> int:
        if os.path.isdir(directory):
            data = b""
            dirs = os.listdir(directory)
            
            for i in dirs:
                if os.path.isfile(directory + "/" + i):
                    data += b"F" + i.encode() + b'\x99'
                
                else:
                    data += b"D" + i.encode() + b'\x99'

            if data == b'':
                data = b'\x99'

            encrypted_data = LyerSec.encryptData(data, self.password)
            data = encrypted_data[0] + encrypted_data[1] + encrypted_data[2]

        else:
            data = struct.pack(">c", b'\x00')

        packet = bytearray(PREFIX_SIZE + len(data) + MD5_SIZE + PREFIX_SIZE)
        packet[: PREFIX_SIZE] = struct.pack(">i", 0)
        packet[PREFIX_SIZE : -PREFIX_SIZE-MD5_SIZE] = data
        packet[-PREFIX_SIZE-MD5_SIZE : -PREFIX_SIZE] = hashlib.md5(data).digest()
        
        packet[-PREFIX_SIZE :] = struct.pack(">i", 0)

        packet = packet[:PREFIX_SIZE] + packet[PREFIX_SIZE : -PREFIX_SIZE].replace(b"\x00\x00\x00\x00", b"\xff\x00\x00\x00\x00") + packet[-PREFIX_SIZE:]

        self.conn.send(packet)

        return len(packet)
    
    
    def decodeDirectory(self, packet: bytes):

        packet = packet[:PREFIX_SIZE] + packet[PREFIX_SIZE : -PREFIX_SIZE].replace(b"\xff\x00\x00\x00\x00", b"\x00\x00\x00\x00") + packet[-PREFIX_SIZE:]
        packet = packet[PREFIX_SIZE : -PREFIX_SIZE]


        if hashlib.md5(packet[: -MD5_SIZE]).digest() == packet[-MD5_SIZE :]:
            packet = packet[: -MD5_SIZE]
            nonce = packet[:16]
            encrypted_data = packet[16:-16]
            tag = packet[-16:]
            
            data = LyerSec.decryptData(encrypted_data, self.password, nonce, tag)

            return data

        else:
            raise RuntimeError("Data integrity check failed")
        
    
    def disasGet(self, packet: bytes):
        if LyerCommand.get(packet) == 1:
            packet = packet[:PREFIX_SIZE] + packet[PREFIX_SIZE : -PREFIX_SIZE].replace(b"\xff\x00\x00\x00\x00", b"\x00\x00\x00\x00") + packet[-PREFIX_SIZE:]
            packet = packet[PREFIX_SIZE + COMMAND_SIZE: -PREFIX_SIZE]

            if hashlib.md5(packet[: -MD5_SIZE]).digest() == packet[-MD5_SIZE: ]:
                packet = packet[: -MD5_SIZE]
                nonce = packet[:16]
                encrypted_data = packet[16:-16]
                tag = packet[-16:]

                data = LyerSec.decryptData(encrypted_data, self.password, nonce, tag)

                return data
            else:
                raise RuntimeError("Data integrity check failed")

        else:
            raise RuntimeError("Missmatching Command")
        
    
class LyerTranfer:
    def __init__(self, password: bytes, conn: Connection) -> None:
        if type(password) == bytes and LyerChecker.isDigSha256(password):
            self.password = password
            self.conn = conn
        
        else:
            raise ValueError("Invalid arguments - password = sha256; conn = Connection")
        
    
    def sendFile(self, data: bytes, destination: str):
        """ Send a encrypted file """

        data = LyerSec.encryptData(data, self.password)

        if b"\xff\x99\x99\x99\x99" in data:
            data.replace(b"\xff\x99\x99\x99\x99", b"\x00\xff\x99\x99\x99\x99")

        elif b"\x99\x99\x99\x99" in data:
            data.replace(b"\x99\x99\x99\x99", b'\xff\x99\x99\x99\x99')

        check = hashlib.md5(data[0] + data[1] + data[2]).digest()
        data = data[0] + data[1] + data[2] + b"\x99\x99\x99\x99" + destination.encode()

        packet = bytearray((PREFIX_SIZE * 2) + COMMAND_SIZE + len(data) + MD5_SIZE)

        packet[:PREFIX_SIZE] = struct.pack(">i", 0)
        packet[PREFIX_SIZE : PREFIX_SIZE + COMMAND_SIZE] = struct.pack(">h", 2)
        packet[PREFIX_SIZE + COMMAND_SIZE : -MD5_SIZE - PREFIX_SIZE] = data
        packet[-MD5_SIZE - PREFIX_SIZE : -PREFIX_SIZE] = check
        packet[-PREFIX_SIZE :] = struct.pack(">i", 0)

        packet = packet[:PREFIX_SIZE] + packet[PREFIX_SIZE : -PREFIX_SIZE].replace(b"\x00\x00\x00\x00", b"\xff\x00\x00\x00\x00") + packet[-PREFIX_SIZE:]

        self.conn.send(packet)
    

    def decodeFile(self, data: bytes) -> bytes | None:
        packet = packet[:PREFIX_SIZE] + packet[PREFIX_SIZE : -PREFIX_SIZE].replace(b"\xff\x00\x00\x00\x00", b"\x00\x00\x00\x00") + packet[-PREFIX_SIZE:]

        if b"\x00\xff\x99\x99\x99\x99" in data:
            data = data.replace(b"\x00\xff\x99\x99\x99\x99", b"\xff\x99\x99\x99\x99")

        elif b"\xff\x99\x99\x99\x99" in data:
            data = data.replace(b"\xff\x99\x99\x99\x99", b"\x99\x99\x99\x99")

        directory = data.split(b"\x99\x99\x99\x99")[-1][:-MD5_SIZE-PREFIX_SIZE]


        if LyerChecker.checkPacket(data):
            data = data[PREFIX_SIZE + COMMAND_SIZE : -PREFIX_SIZE]
            check = data[-MD5_SIZE :]
            data = data[: -4-len(directory)-MD5_SIZE]


            if hashlib.md5(data).digest() == check:
                nonce = data[:16]
                encrypted_data = data[16:-16]
                tag = data[-16:]

                data = LyerSec.decryptData(encrypted_data, self.password, nonce, tag)

                return (data, directory)

            else:
                raise RuntimeError("Data integrity check failed")

        else:
            return None