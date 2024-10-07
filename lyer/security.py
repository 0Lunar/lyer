import hashlib
import struct
import binascii
from .checker import LyerChecker
from .exceptions import *
import mysql.connector
from mysql.connector import errorcode
import os 

if os.name == "nt":
    from Crypto.Cipher import AES
else:
    from Cryptodome.Cipher import AES  


COMMAND_SIZE = 2
PREFIX_SIZE = 4
SHA256_SIZE = 32
MD5_SIZE = 16
        


""" LyerSec class

It's used to manage the authentication process
"""

class LyerSec:
    def unhexPassword(password: str) -> bytes | None:
        """ convert sha256 from hexdigest to digest """
        if not LyerChecker.isHexSha256(password):
            return None
        
        return binascii.unhexlify(password)


    def unhexUser(username: str) -> bytes | None:
        """ convert md5 from hexdigest to digest """
        if not LyerChecker.isHexMd5(username):
            return False
        
        return binascii.unhexlify(username)


    def hashPassword(password: bytes) -> bytes:
        """ Return the password hashed in sha256 """

        return hashlib.sha256(password).digest()
    
    
    def hashUser(username: bytes) -> bytes:
        """ Return the username hashed in md5 """

        return hashlib.md5(username).digest()

    
    def encryptData(data: bytes, password: bytes) -> tuple[bytes] | None:
        if type(password) != bytes or not LyerChecker.isDigSha256(password):
            return None

        nonce = os.urandom(16)
        cipher = AES.new(password, AES.MODE_GCM, nonce=nonce)

        ciphertext, tag = cipher.encrypt_and_digest(data)

        return (nonce, ciphertext, tag)


    def decryptData(data: bytes, password: bytes, nonce: bytes, tag: bytes) -> bytes | None:
        if type(password) != bytes or type(nonce) != bytes or type(tag) != bytes or not LyerChecker.isDigSha256(password) or len(nonce) != 16 or len(tag) != 16:
            return None

        cipher = AES.new(password, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted_data = cipher.decrypt_and_verify(data, tag)
        
            return decrypted_data

        except ValueError:
            raise ValueError("Error decrypting data: Integrity check failed (invalid tag or corrupted data)")


class LyerPacketAuth:
    def AuthPacket(username: bytes, password: bytes) -> bytearray | None:
        """ Return the authentication packet """
        
        if len(username) != MD5_SIZE or len(password) != SHA256_SIZE:
            return None

        packet = bytearray((PREFIX_SIZE * 2) + COMMAND_SIZE + SHA256_SIZE + (MD5_SIZE * 2))
        
        packet[: PREFIX_SIZE] = struct.pack(">i", 0)
        packet[PREFIX_SIZE : PREFIX_SIZE + COMMAND_SIZE] = struct.pack(">h", 0)
        packet[PREFIX_SIZE + COMMAND_SIZE : MD5_SIZE + PREFIX_SIZE + COMMAND_SIZE] = username
        packet[MD5_SIZE + PREFIX_SIZE + COMMAND_SIZE : MD5_SIZE + PREFIX_SIZE + SHA256_SIZE + COMMAND_SIZE] = password
        packet[MD5_SIZE + PREFIX_SIZE + SHA256_SIZE + COMMAND_SIZE : (MD5_SIZE * 2) + PREFIX_SIZE + SHA256_SIZE + COMMAND_SIZE] = hashlib.md5(packet[PREFIX_SIZE : -MD5_SIZE-PREFIX_SIZE]).digest()   #like crc
        packet[-PREFIX_SIZE:] = struct.pack(">i", 0)

        return packet


    def AuthPacketDisas(packet: bytes) -> dict | None:
        """ Disassemble the authentication packet returning username and password in hash
            username: md5
            password: sha256     
        """

        newPacket = {"username": None, "password": None}


        if packet[0:PREFIX_SIZE] != struct.pack(">i", 0) or packet[-PREFIX_SIZE :] != struct.pack(">i", 0) or packet[PREFIX_SIZE : PREFIX_SIZE + COMMAND_SIZE] != struct.pack(">h", 0) or len(packet) != (PREFIX_SIZE * 2) + COMMAND_SIZE + SHA256_SIZE + (MD5_SIZE * 2) or hashlib.md5(packet[PREFIX_SIZE : -PREFIX_SIZE-MD5_SIZE]).digest() != packet[-MD5_SIZE-PREFIX_SIZE: -PREFIX_SIZE]:
            return None
        
        newPacket.update({"username": packet[PREFIX_SIZE + COMMAND_SIZE : COMMAND_SIZE + MD5_SIZE + PREFIX_SIZE]})
        newPacket.update({"password": packet[PREFIX_SIZE + MD5_SIZE + COMMAND_SIZE : COMMAND_SIZE + PREFIX_SIZE + MD5_SIZE + SHA256_SIZE]})

        return newPacket
    


""" DatabaseManager class

It's used to manage to the mysql database
"""

class DatabaseManager:
    def __init__(self, user: str, password: str, host: str, port: int = 3306) -> None:
        if LyerChecker.isIp(host) and LyerChecker.isPort(port) and type(user) == str and type(password) == str:
            self.user = user
            self.password = password
            self.host = host
            self.port = port
            self.conn = None
        
        else:
            raise ValueError
        
    
    def connect(self):
        """ Connect to the server, return the connection """

        config = {
            'user': self.user,
            'password': self.password,
            'host': self.host,
            'port': self.port,
            'raise_on_warnings': True
        }

        try:
            self.conn = mysql.connector.connect(**config)
            return self.conn

        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                raise AuthenticationError
            
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                raise DatabaseNotFound

            else:
                raise err
            

    def checkConnection(self) -> bool:
        if self.conn is not None:
            return True
        
        return False


    def getCredentials(self) -> list[dict] | None:
        """ Get all the username and password from the database 
        return a dict
        """

        if not self.checkConnection():
            return None

        credentials = []
        
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT username, password FROM auth")
                result = cursor.fetchall()

                for acc in result:
                    credentials.append({"username": acc[0], "password": acc[1]})

            return credentials
    
        except mysql.connector.Error as err:
            raise RuntimeError(f"Error getting credentials: {err}")
        

    def addCredentials(self, username: str, password: str) -> bool:
        """ Add a new account to the database """

        newUsername = hashlib.md5(username.encode()).hexdigest()
        newPassword = hashlib.sha256(password.encode()).hexdigest()

        with self.conn.cursor() as cursor:
            try:
                cursor.execute(f"INSERT INTO auth (username, password) VALUES (%s, %s)", (username, password))
                self.conn.commit()
                return True
        
            except mysql.connector.Error as err:
                raise RuntimeError("Error adding username and password")
    
        
    def close(self) -> bool:
        """ Close the connection with the database
        return True if the connection is closed successfully
        return False if the connection doesn't exist
        raise RuntimeError if there's a problem closing the connection
        """

        if self.conn is not None:
            try:
                self.conn.close()
                self.conn = None
                return True
            
            except Exception:
                raise RuntimeError("Error closing the connection with the database")
        
        return False