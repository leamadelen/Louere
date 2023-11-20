import os
os.environ['DATABASE_URL'] = 'sqlite://'  # bruker en in-memory database for tester

import unittest
from flask import current_app
from app import app, db
from app.models import User


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['WTF_CSRF_ENABLED'] = False  # no CSRF during tests
        self.appctx = self.app.app_context()
        self.appctx.push()
        db.create_all()
        self.populate_db()
        self.client = self.app.test_client()

    def tearDown(self):
        db.drop_all()
        self.appctx.pop()
        self.app = None
        self.appctx = None
        self.client = None

    def populate_db(self):
        user = User(username='ayla', email='ayla@example.com')
        user.set_password('hello')
        db.session.add(user)
        db.session.commit()

    def login(self):
        self.client.post('/login', data={
            'username': 'ayla',
            'password': 'hello',
        })

    def test_app(self):
        assert self.app is not None
        assert current_app == self.app

    def test_home_page_redirect(self):
        response = self.client.get('/', follow_redirects=True)
        assert response.status_code == 200
        assert response.request.path == '/login'

    def test_registration_form(self):
        response = self.client.get('/register')
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        assert 'name="username"' in html
        assert 'name="email"' in html
        assert 'name="password"' in html
        assert 'name="password2"' in html
        assert 'name="submit"' in html

    def test_register_user(self):
        response = self.client.post('/register', data={
            'username': 'bobby',
            'email': 'bob@example.com',
            'password': '12345',
            'password2': '12345',
        }, follow_redirects=True)
        assert response.status_code == 200
        assert response.request.path == '/register' 

        # login with new user
        response = self.client.post('/login', data={
            'username': 'bobby',
            'password': '12345',
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'Hi, bobby!'

    def test_register_user_mismatched_passwords(self):
        response = self.client.post('/register', data={
            'username': 'bobby',
            'email': 'bob@example.com',
            'password': '12345',
            'password2': 'foo',
        })
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert '[Field must be equal to password.]' in html

    def test_write_post(self):
        self.login()
        response = self.client.post('/', data={'post': 'Welcome to my page'},
                                    follow_redirects=True)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'Your post is now live!'
        assert 'Welcome to my page!'