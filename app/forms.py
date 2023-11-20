from operator import le
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Length
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from zxcvbn import zxcvbn
#import re

class LoginForm(FlaskForm):
    username = StringField('Brukernavn', validators=[DataRequired()])
    password = PasswordField('Passord', validators=[DataRequired()])
    remember_me = BooleanField('')
    submit = SubmitField('Logg inn')

class RegistrationForm(FlaskForm):
    username = StringField('Brukernavn', validators=[DataRequired(), Length(min=2, max=20, message="Brukernavn mellom 2-20 tegn")]) # legger til lenght (navn mellom 2-20) 
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Passord (minst 8 tegn)', validators=[DataRequired(), Length(min=8, max=64, message="Passord minst 8 tegn. ")]) # passord mellom 8 og 64 tegn Length(min=8, max=64, message="Passord minst 8 tegn")
    password2 = PasswordField(
        'Gjenta passord', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrer')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Ugyldig brukernavn.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Ugyldig epost.')
    
    def validate_password(self, password):
        password = password.data
        results = zxcvbn(password)
        str = ""
       # str1 = ""
        #str2 =""
        if results['score'] < 3:
            str += "Passordstyrken er for lav."
            if results['feedback']['warning']:
                str += f" Warning: {results['feedback']['warning']}."
            #if results['feedback']['suggestions']:
                #str2 += f" Tips: {results['feedback']['suggestions']}."
            raise ValidationError(str)


class KontaktForm(FlaskForm):
     name = StringField('Navn', validators=[DataRequired()])
     email = StringField('Email', validators=[DataRequired()])
     message = StringField('Melding', validators=[DataRequired()])
     submit = SubmitField('Kontakt')

class EditProfileForm(FlaskForm):
    username = StringField('Brukernavn', validators=[DataRequired(), Length(min=2, max=20, message="Brukernavn mellom 2-20 tegn")])
    about_me = TextAreaField('Om meg', validators=[Length(min=0, max=140)])
    submit = SubmitField('Send inn')

    def __init__(self, original_username, original_about_me, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_about_me = original_about_me

    def validate_username(self, username):
        if self.username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Endring mislyktes.')
            

class EmptyForm(FlaskForm):
    submit = SubmitField('Submit')

class PostForm(FlaskForm):
    file = FileField('Last opp bilde:', validators=[
        DataRequired()])
    post = TextAreaField('Lei ut noe: ', validators=[
        DataRequired(), Length(min=1, max=140)])
    submit = SubmitField('Legg ut')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')