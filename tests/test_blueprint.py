import os
import unittest
from app import create_app, db 
from flask import Flask, request, session, current_app

class ApplicationTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing_config')
        self.req_ctx = self.app.test_request_context('http://127.0.0.1/user?name=FatCat')
        self.req_ctx.push()
        db.create_all()

    def test_app_exists(self): 
        self.assertFalse(session is None)
    
    def test_req_context(self):
        session['name'] = request.query_string
        self.assertNotEqual(session['name'], request.args.get("name"))

    def test_app_is_testing(self):
        self.assertTrue(current_app.config['TESTING'])

    def test_app_database(self):
        self.assertEqual(self.app.config['SQLALCHEMY_DATABASE_URI'], os.getenv('URLT'))
    
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.req_ctx.pop()
