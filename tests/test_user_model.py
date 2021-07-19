import unittest
from app import create_app, db
from app.blueprint_models import User
from werkzeug.security import generate_password_hash, check_password_hash


class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing_config')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):
        user = User()
        user.password_hash = 'cat'
        self.assertTrue(user.password_hash)

    def test_no_password_getter(self):
        user = User()
        user.password_hash = 'cat'
        with self.assertRaises(AttributeError):
            user.set_password

    def test_password_verification(self):
        user = User()
        user.password_hash = generate_password_hash('cat')
        self.assertTrue(check_password_hash(user.password_hash, 'cat'))
        self.assertFalse(check_password_hash(user.password_hash, 'dog'))

    def test_password_salts_are_random(self):
        user1 = User()
        user1.password_hash = generate_password_hash('cat')
        user2 = User()
        user2.password_hash = generate_password_hash('cat')
        self.assertTrue(user1.password_hash != user2.password_hash)
