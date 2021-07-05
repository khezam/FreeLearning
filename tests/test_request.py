import unittest
from flask import Flask, request, session

class ApplicationTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'test'
        self.req_ctx = self.app.test_request_context('http://127.0.0.1/user?name=FatCat')
        self.req_ctx.push()
    
    def test_req_context(self):
        session['name'] = request.query_string
        self.assertNotEqual(session['name'], request.args.get("name"))
    
    def tearDown(self):
        self.req_ctx.pop()


