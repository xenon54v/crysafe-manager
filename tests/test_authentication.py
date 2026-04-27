from src.core.crypto.authentication import AuthenticationService

def test_authentication_login():
    auth = AuthenticationService()

    session = auth.login("test_user")

    assert session.is_authenticated is True
    assert session.username == "test_user"
    assert session.login_time is not None

def test_authentication_logout():
    auth = AuthenticationService()

    auth.login("test_user")
    auth.logout()

    assert auth.is_authenticated() is False