import unittest
from flask import Flask, current_app, request, session

class ApplicationTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'test'
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()
    
    def test_app_context(self):
        self.assertEqual('test_app', current_app.name)
    
    def tearDown(self):
        self.app_ctx.pop()

