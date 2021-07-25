import re
import unittest
from app import create_app, db
from app.blueprint_models import User, Role

class FlaskClientTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing_config')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client(use_cookies=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertFalse(b'Stranger' in response.data)

    def test_register_and_login(self):
        # register a new account
        response = self.client.post('/auth/register', data={
            'email': 'cat@cat.com',
            'username': 'kitty',
            'password': 'kitty',
            'confirm_password': 'kitty'
        })
        self.assertEqual(response.status_code, 302)

        # send a confirmation token to the user via email
        user = User.query.filter_by(email='cat@cat.com').first()
        token = user.generate_confirmation_token('confirm')
        response = self.client.get('/auth/confirm/{}/{}'.format(user.id, token), follow_redirects=True)
        user.confirm(token)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'You have confirmed your account' in response.data)

        # try to logout without being logged in.
        response = self.client.get('/auth/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Please log in to access this page.' in response.data)
