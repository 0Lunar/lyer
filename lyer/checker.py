import struct


SHA256_SIZE = 32
MD5_SIZE = 16


class LyerChecker:
    def isIp(ip: str) -> bool:
        if type(ip) != str:
            return False

        if len(ip.split(".")) != 4:
            return False

        check = False

        for i in ip.split("."):

            if i.isdigit() and len(i) < 4:
                if int(i) < 0 or int(i) > 255:
                    return False

            else:
                return False

        return True
    

    def isPort(port: int) -> bool:
        if type(port) != int:
            return False
    
        if port > (2**16) - 1 or port < 0:
            return False
    
        return True
    
    
    def isHexSha256(string: str) -> bool:
        hexdigit = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f']

        if len(string) != 64:
            return False

        for i in string:
            if i not in hexdigit:
                return False

        return True


    def isHexMd5(string: str) -> bool:
        hexdigit = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f']

        if len(string) != 32:
            return False

        for i in string:
            if i not in hexdigit:
                return False

        return True
    

    def isDigSha256(sh: bytes) -> bool:
        if type(sh) != bytes:
            return False

        return len(sh) == SHA256_SIZE


    def isDigMd5(sh: bytes) -> bool:
        if type(sh) != bytes:
            return False

        return len(sh) == MD5_SIZE
    

    def checkPacket(packet: bytes) -> bool:
        return len(packet) > 8 and packet.startswith(struct.pack(">i", 0)) and packet.endswith(struct.pack(">i", 0))
        