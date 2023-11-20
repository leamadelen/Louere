from flask import Flask, url_for, redirect, render_template, request, abort
from flask.helpers import url_for
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_moment import Moment
from flask_socketio import SocketIO
# importere Admin
#from app import app, db
#from app.forms import LoginForm
#from flask_admin import Admin, BaseView, expose#, ModelView
#from flask_admin import ModelView
#from flask_login import current_user, login_user, logout_user, login_required
#from app.models import User
#from flask_login import UserMixin

#from flask_appbuilder import ModelViews
#from flask import url_for
import os
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_security.utils import encrypt_password
import flask_admin as admin
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from flask_appbuilder import ModelView
from flask_mail import Mail


UPLOAD_FOLDER = '../louer/app/static'

# Admin
#Create custum Admin View
class MyAdminView(admin.BaseView):
    @admin.expose('/')
    def index(self):
        # Get URL for the test view method
        return self.render('myadmin.html')

    # Only logged in users have access to view function
    #def is_accessible(self):
    #    return login.current_user.is_authenticated()

    
    # redirect the user to login page if authentication fails
    #def _handle_view(self, name, **kwargs): #, name, **kwargs
    #    if not self.is_accessible():
    #        return redirect(url_for('login', next=request.url))


class AnotherAdminView(admin.BaseView):
    @admin.expose('/')
    def index(self):
        return self.render('anotheradmin.html')

    @admin.expose('/test/')
    def test(self):
        return self.render('test.html')



app = Flask(__name__, static_url_path='/static', template_folder='templates') # uten template_folder-delen
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
moment = Moment(app)
mail = Mail(app)
app.debug = True
# admin

#@app.route('/')
#def index():
#    return '<a href="/admin/">Click me to get to Admin!</a>'

######admin = Admin(app)
# Create admin interface
admin = admin.Admin(name="Forside", template_mode='bootstrap4')
admin.add_view(MyAdminView(name="side1", category='Hvilken side vil du til?'))
admin.add_view(AnotherAdminView(name="side2", category='Hvilken side vil du til?'))
admin.init_app(app)

# override endpoint name
#admin.add_view(MyView(endpoint='testadmin'))
# In this case, generate links by concatenating the view method name with an endpoint
#url_for('testadmin.index')

#admin.init_app(app)
#admin.add_view(MyView(name='Hello 1', endpoint= 'test1', category='Test'))
#admin.add_view(MyView(name='Hello 2', endpoint='test2', category='Test'))
#admin.add_view(MyView(name='Hello 3', endpoint='test3', category='Test'))
#admin.add_view(MyView(endpoint='testadmin')) #GJØR AT URLKODEN HETER TESTADMIN
#url_for('testadmin.index')

# Admin page for the User model
from flask_admin.contrib.sqla import ModelView
from app.models import User

#####admin.add_view(ModelView(User, db.session))

# Manage files on server (upload, delete,rename, etc)
from flask_admin.contrib.fileadmin import FileAdmin
import os.path as op

#####path = op.join(op.dirname(__file__), 'static')
#####admin.add_view(FileAdmin(path, '/static/',name='Static Files'))

from app import routes, models

