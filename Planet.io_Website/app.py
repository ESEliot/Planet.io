import copy
import csv
import bcrypt
from django.core import mail
from flask import Flask, render_template, redirect, flash, session, request
from flask_login import UserMixin, LoginManager, login_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, form, SelectField, FileField
from wtforms.fields.html5 import EmailField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_mail import Message, Mail

app = Flask(__name__)

# All login managers and mail
mail = Mail()
login_manager = LoginManager()
app.secret_key = 'allo'
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['USE_SESSION_FOR_NEXT'] = True

# ROUTE ----------------------------------------------------------------------------------------------------
# Main route - Home
@app.route('/')
def base_template():
    return render_template("base_template.html", name=session.get('name'), username=session.get('username'))

# Challenges route - Challenges Page
@app.route('/challenges')
def challenges_template():
    return render_template("challenges_template.html", name=session.get('name'), username=session.get('username'))

# News route - News Page
@app.route('/news')
def news_template():
    return render_template("news_template.html", name=session.get('name'), username=session.get('username'))

# Library Route - Library page
@app.route('/library')
def library_template():
    return render_template("Library_template.html", name=session.get('name'), username=session.get('username'))

# Login route - Login Page
@app.route('/login')
def login_template():
    return render_template("Log_in_template.html", name=session.get('name'), username=session.get('username'))

# Projects route - Project Page
@app.route('/projects')
def projects_template():
    return render_template("Projects_template.html", name=session.get('name'), username=session.get('username'))

# Solutions route - Solutions Page
@app.route('/solutions')
def solutions_template():
    return render_template("Solutions_template.html", name=session.get('name'), username=session.get('username'))

# About Us route - About Us page
@app.route('/aboutus')
def aboutus_template():
    return render_template("aboutus_template.html", name=session.get('name'), username=session.get('username'))

# Registration route - Registration Page
@app.route('/registrationform')
def registration_template():
    form = RegisterForm()
    return render_template("registration_template.html", form=form, name=session.get('name'), username=session.get('username'))

# Users Table route - Users Table page (Only accessible for Admin)
@app.route('/userstable')
def userstable_template():
    with open('data/users.csv') as f:
        users_list = list(csv.reader(f))[1:]
    return render_template("users_template.html", form=form, name=session.get('name'), username=session.get('username'), users_list=users_list)
# END ROUTE ----------------------------------------------------------------------------------------------------

# USER ----------------------------------------------------------------------------------------------------
# User class - Defines a user and its attributes : username, email, name, password
class User(UserMixin):
    def __init__(self, username, email, name, password=None):
        self.id = username
        self.email = email
        self.name = name
        self.password = password
# END USER ----------------------------------------------------------------------------------------------------


# REGISTRATION ----------------------------------------------------------------------------------------------------
# RegisterForm - Form for registration - Atrributes of the form: name, username, email, password, password2
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    username = StringField('Username', validators=[InputRequired()])
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(),
                                                     Length(8)])
    password2 = PasswordField('Repeat password',
                              validators=[InputRequired(),
                                          EqualTo('password', message='Passwords must match.')])

# Method to find user in the users file
def find_user(username):
    with open('data/users.csv') as f:
        for user in csv.reader(f):
            if username == user[0]:
                return User(*user)
    return None


# Register route - Handle all registration backend
@app.route('/register', methods=['GET', 'POST'])
def register():
    form1 = RegisterForm(request.form)
    print(form1.errors)
    if form1.validate_on_submit():
        finduser = find_user(form1.username.data)
        if finduser:
            flash('This username already exists. Choose another one please')
            return render_template('registration_template.html', form=form1)
        if not finduser:
            salt = bcrypt.gensalt()
            password = bcrypt.hashpw(form1.password.data.encode(),
                                     salt)
            with open('data/users.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerow([form1.username.data,
                                 form1.email.data,
                                 form1.name.data,
                                 password.decode()])
                flash('Registered successfully.')
        session['name'] = form1.name.data
        return render_template('registration_response_template.html', form=form1, name=session.get('name'))

    message = copy.deepcopy(form1.errors)
    return render_template('registration_template.html', form=form1, message=message)
# END REGISTRATION ----------------------------------------------------------------------------------------------------


# LOGIN ------------------------------------------------------------------------------------------------------------
# Login Manager that returns user
@login_manager.user_loader
def load_user(user_id):
    user = find_user(user_id)
    # user could be None
    if user:
        # if not None, hide the password by setting it to None
        user.password = None
    return user


# LoginForm - Form to login - Attributes: username, password
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])


# Handleogin route - Handles all login backend
@app.route('/handlelogin', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = find_user(form.username.data)
        # user could be None
        # passwords are kept in hashed form, using the bcrypt algorithm
        if user and bcrypt.checkpw(form.password.data.encode(),
                                   user.password.encode()):
            login_user(user)
            flash('Logged in successfully.')
            next_page = session.get('next', '/')
            session['next'] = '/'
            print(user.name)
            print(form.username.data)
            session['name'] = user.name
            session['username'] = form.username.data
            print('Log in good')
            return redirect(next_page)
        else:
            flash('Incorrect username/password.')
    return render_template('Log_in_template.html', form=form, name=session.get('name'), username=session.get('username'))
# ENDLOGIN ------------------------------------------------------------------------------------------------------------


# LOGOUT ------------------------------------------------------------------------------------------------------------
# Logout route - Logs out the session
@app.route('/logout')
def logout():
    session.clear()
    return render_template('base_template.html')
# END LOGOUT ----------------------------------------------------------------------------------------------------------


# CREATE PROJECT ------------------------------------------------------------------------------------------------------
# Project class - Defines a Project and its attributes
class Project(FlaskForm):
    challengechoices = [('o1', 'Land Pollution'), ('o2', 'Water Pollution'), ('o3', 'Ice Melting')
                 ,('o4', 'Transport'), ('o5', 'Agriculture'), ('o6', 'Water Scarcity')]
    for o in challengechoices:
        option, name = o
        print(name)
    name = StringField('Name', validators=[InputRequired()])
    challenge = SelectField('Challenges',
             validators=[InputRequired()],
             choices=challengechoices)
    description = TextAreaField('Description', validators=[InputRequired()])
    file = FileField('Upload any useful file here for the community:', validators=[InputRequired()])
    render_kw = {'required': True}


# Create Project route - Page to Create a Project
@app.route('/createproject', methods=['GET', 'POST'])
def createproject_template():
    form = Project(request.form)
    print(form.errors)
    if form.validate_on_submit():
        with open('data/projects.csv', 'a') as f:
            writer = csv.writer(f)
            writer.writerow([form.name,
                            form.challenge,
                            form.description,
                            form.file])
            flash('Project Submitted!')
        return render_template("createproject_response_template.html", form=form, name=session.get('name'), username=session.get('username'))
    return render_template("createproject_template.html", form=form)

# END CREATE PROJECT --------------------------------------------------------------------------------------------------


# FORGOT PASSWORD ------------------------------------------------------------------------------------------------------
# Forgot form - Forgot password Page
class ForgotForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])


# Reset Password Form
class PasswordResetForm(FlaskForm):
    current_password = PasswordField('Password', validators=[InputRequired(),
                                                     Length(8)])
# END FORGOT PASSWORD -------------------------------------------------------------------------------------------------


# MAIL ------------------------------------------------------------------------------------------------------------
# Mail config
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['MAIL_DEFAULT_SENDER'] = None
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_SUPPRESS_SEND'] = app.testing
app.config['MAIL_ASCII_ATTACHMENTS'] = False


# Initiate mail
mail.init_app(app)


# Forgot Password route - handle all forgot password backend
@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword_template():
    form = ForgotForm(request.form)
    if form.validate_on_submit():
        msg = Message('Reset your password with the link below: ', recipients=[form.email])
        mail.send(msg)
    return render_template("forgotpassword_template.html", name=session.get('name'), username=session.get('username'), form=form)
# END MAIL ------------------------------------------------------------------------------------------------------------


if __name__ == '__main__':
    app.secret_key = 'allo'
    app.run()
