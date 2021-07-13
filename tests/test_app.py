import unittest
from flask_mail import Message
from index import mail, app
from flask import Flask, current_app, request, session, render_template

class ApplicationTest(unittest.TestCase):
    def setUp(self):
        self.app_ctx = app.app_context()
        self.app_ctx.push()
    
    def test_app_context(self):
        self.assertEqual('index', current_app.name)
    
    def tearDown(self):
        self.app_ctx.pop()

    def test_email(self):
        msg = mail.send_message("Testing!", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'], body='Thank you testing')
        self.assertIsNotNone(msg)
