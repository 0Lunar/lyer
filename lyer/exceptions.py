class AuthenticationError(Exception):
    def __init__(self, message="Nome utente o password errati."):
        super().__init__(message)


class DatabaseNotFound(Exception):
    def __init__(self, message="Database not found") -> None:
        super().__init__(message)