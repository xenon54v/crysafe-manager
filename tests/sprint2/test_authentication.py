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

def test_failed_attempt_counter_increases():
    auth = AuthenticationService()

    attempts1 = auth.register_failed_attempt()
    attempts2 = auth.register_failed_attempt()

    assert attempts1 == 1
    assert attempts2 == 2


def test_successful_login_resets_failed_attempts():
    auth = AuthenticationService()

    auth.register_failed_attempt()
    auth.register_failed_attempt()

    auth.login("test_user")

    attempts = auth.register_failed_attempt()

    assert attempts == 1