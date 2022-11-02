#!/usr/bin/python3
'''auth module'''

import bcrypt
from flask_restplus import abort
from models import storage
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from models.user import User
from uuid import uuid4

authorization = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY'
    }
}


def _hash_password(password: str) -> str:
    """ Returns a salted hash of the input password """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """Returns a string representation of a new UUID"""
    UUID = uuid4()
    return str(UUID)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self.__session = storage.get_session()

    def register_user(self, email: str, password: str) -> User:
        """ Registers a user in the database
        Returns: User Object
        """
        print(email, password)
        
        user = self.__session.query(User).filter_by('email')
        print(">>>>>>>>>>>",user)
        if not user:
            hashed_password = _hash_password(password)
            user = User()
            user.email = email
            user.password = hashed_password

            return user
        else:
            abort(406)

    def valid_login(self, email: str, password: str) -> bool:
        """If password is valid returns true, else, false"""
        try:
            user = self.storage.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        encoded_password = password.encode()

        if bcrypt.checkpw(encoded_password, user_password):
            return True

        return False

    def create_session(self, email: str) -> str:
        """ Returns session ID for a user """
        try:
            user = self.storage.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()

        self.storage.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """It takes a single session_id string argument
        Returns a string or None
        """
        if session_id is None:
            return None

        try:
            user = self.storage.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Updates the corresponding user's session ID to None"""
        try:
            user = self.storage.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self.storage.update_user(user.id, session_id=None)

        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token if user exists"""
        try:
            user = self.storage.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()

        self.storage.update_user(user.id, reset_token=reset_token)

        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Uses reset token to validate update of users password"""
        if reset_token is None or password is None:
            return None

        try:
            user = self.storage.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)
        self.storage.update_user(user.id,
                             hashed_password=hashed_password,
                             reset_token=None)
