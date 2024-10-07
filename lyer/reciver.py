import socket
import struct
from .checker import LyerChecker
from .security import LyerSec, LyerPacketAuth


class Connection:
    def __init__(self, conn: socket.socket, addr: tuple) -> None:
        self.conn = conn
        self.addr = addr

    
    def checkConn(self):
        return False if self.conn == None else True


    def send(self, packet: bytes) -> int:
        if self.checkConn():
            self.conn.send(packet)
    

    def recv(self, bufsize: int):
        if self.checkConn:
            data = self.conn.recv(bufsize)
            return data
    

    def timeout(self, time: float | None):
        self.conn.settimeout(time)


    def close(self):
        if self.checkConn():
            self.conn.close()
            self.conn = None



class LyerReciver:
    def __init__(self, ip: str, port: int) -> None:
        if LyerChecker.isIp(ip) and LyerChecker.isPort(port):
            self.ip = ip
            self.port = port
            self.socket = None
        
        else:
            raise ValueError("Invalid ip/port")
        

    def isInit(self) -> bool:
        """ Check if the reciver is Initialized """
        return isinstance(self.socket, socket.socket)
    

    def initServer(self) -> None:
        """ Initialize the reciver """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
    

    def accept(self, backlog: int = 5) -> Connection | bool:
        """ Accept a new connection and return the Connection class """
        if self.isInit():
            self.socket.listen()
            conn, addr = self.socket.accept()
            
            return Connection(conn, addr)
    
        return False