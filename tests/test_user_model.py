import time
import unittest
from app import create_app, db
from app.blueprint_models import User, Role, AnonymousUser, Permissions
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

    def test_valid_confirmation_token(self):
        user = User()
        user.password_hash = generate_password_hash('cat')
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token('confirm')
        self.assertTrue(user.confirm(token))

    def test_invalid_confirmation_token(self):
        user1 = User()
        user1.password_hash = generate_password_hash('cat')
        user2 = User()
        user2.password_hash = generate_password_hash('cat')
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()
        token = user1.generate_confirmation_token('confirm')
        self.assertFalse(user2.confirm(token))

    def test_expired_confirmation_token(self):
        user = User()
        user.password_hash = generate_password_hash('cat')
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token(1)
        time.sleep(2)
        self.assertFalse(user.confirm(token))

    def test_valid_email_change_token(self):
        user = User(email='cat@cat.com', password_hash=generate_password_hash('cat'))
        db.session.add(user)
        db.session.commit()
        token = user.generate_email_change_token('change_email', new_email='fatcat@fatcat.com')
        self.assertTrue(user.confirm_email_change_token(token))
        self.assertTrue(user.email == 'fatcat@fatcat.com')

    def test_invalid_email_change_token(self):
        user = User(email='cat@cat.com', password_hash=generate_password_hash('cat'))
        db.session.add(user)
        db.session.commit()
        token = user.generate_email_change_token('change_email', new_email='fatcat@fatcat.com')
        self.assertTrue(user.confirm_email_change_token(token))
        self.assertFalse(user.email == 'skinnycat@skinnycat.com')
    
    def test_invalid_email_change_token(self):
        user1 = User(email='fatcat@fatcat.com', password_hash=generate_password_hash('cat'))
        user2 = User(email='skinnycat@skinnycat.com', password_hash=generate_password_hash('cat'))
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()
        token = user1.generate_email_change_token('change_email', new_email='chubbycat@chubbycat.com')
        self.assertFalse(user2.confirm_email_change_token(token))
        self.assertTrue(user2.email == 'skinnycat@skinnycat.com')
    
    def test_duplicate_email_change_token(self):
        user1 = User(email='fatcat@fatcat.com', password_hash=generate_password_hash('cat'))
        user2 = User(email='skinnycat@skinnycat.com', password_hash=generate_password_hash('cat'))
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()
        token = user2.generate_email_change_token('change_email', new_email='fatcat@fatcat.com')
        self.assertFalse(user2.confirm_email_change_token(token))
        self.assertTrue(user2.email == 'skinnycat@skinnycat.com')

    def test_valid_forgot_password_token(self):
        user = User(email='cat@cat.com', password_hash=generate_password_hash('cat'))
        db.session.add(user)
        db.session.commit()
        token = user.generate_forgot_password_token('set_password')
        self.assertTrue(user.confirm_forgot_password_token(token))

    def test_invalid_forgot_password_token(self):
        user = User(email='cat@cat.com', password_hash=generate_password_hash('cat'))
        db.session.add(user)
        db.session.commit()
        token = user.generate_forgot_password_token('set_password')
        self.assertFalse(user.confirm_forgot_password_token(token+'s'))

    def test_user_role(self):
        user = User(email='john@example.com', password_hash=generate_password_hash('cat'))
        self.assertTrue(user.can_user(Permissions.FOLLOW))
        self.assertTrue(user.can_user(Permissions.COMMENT))
        self.assertTrue(user.can_user(Permissions.WRITE))
        self.assertTrue(user.can_user(Permissions.MODERATE))
        self.assertTrue(user.can_user(Permissions.ADMIN))

    def test_moderator_role(self):
        role = Role.query.filter_by(name='Moderator').first()
        user = User(email='john@example.com', password_hash=generate_password_hash('cat'), role=role)
        self.assertTrue(user.can_user(Permissions.FOLLOW))
        self.assertTrue(user.can_user(Permissions.COMMENT))
        self.assertTrue(user.can_user(Permissions.WRITE))
        self.assertTrue(user.can_user(Permissions.MODERATE))
        self.assertTrue(user.can_user(Permissions.ADMIN))

    def test_administrator_role(self):
        role = Role.query.filter_by(name='Administrator').first()
        user = User(email='john@example.com', password_hash=generate_password_hash('cat'), role=role)
        self.assertTrue(user.can_user(Permissions.FOLLOW))
        self.assertTrue(user.can_user(Permissions.COMMENT))
        self.assertTrue(user.can_user(Permissions.WRITE))
        self.assertTrue(user.can_user(Permissions.MODERATE))
        self.assertTrue(user.can_user(Permissions.ADMIN))

    def test_anonymous_user(self):
        user = AnonymousUser()
        self.assertFalse(user.can(Permissions.FOLLOW))
        self.assertFalse(user.can(Permissions.COMMENT))
        self.assertFalse(user.can(Permissions.WRITE))
        self.assertFalse(user.can(Permissions.MODERATE))
        self.assertFalse(user.can(Permissions.ADMIN))