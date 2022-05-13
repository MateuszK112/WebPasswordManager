from flask import Flask, flash, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, ValidationError, SubmitField
from wtforms.validators import Length, InputRequired, Email, Regexp
from flask_mail import Mail, Message
from functools import wraps
from hash_password import safe_password
from symetric_password import symetric_encode, symetric_decode
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import time as tm

app = Flask(__name__)

app.config['SECRET_KEY'] = '123().adaNFIA/"K-supersecretkey!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project_app_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'texterdexter1@gmail.com'
app.config['MAIL_PASSWORD'] = 'dextertexter1-' 

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(16))
    password = db.Column(db.String(254))
    email = db.Column(db.String(254))
    salt = db.Column(db.String(254))
    passwordss = db.relationship("Passwords", secondary = 'userpasswords')

    def get_reset_token(self, expiration_time = 600):

        serial = Serializer(app.config['SECRET_KEY'], expiration_time)

        return serial.dumps({'user_id' : self.id}).decode('utf-8')

    @staticmethod 
    def verify_reset_token(token):

        serial = Serializer(app.config['SECRET_KEY'])

        try:
            user_id = serial.loads(token)['user_id']
        except:
            return None
        
        return User.query.get(user_id)

class Passwords(db.Model):
    __tablename__ = 'passwords'
    id = db.Column(db.Integer, primary_key = True)
    original_owner = db.Column(db.String(16))
    password_data = db.Column(db.String(254))
    site_data = db.Column(db.String(254))
    userss = db.relationship("User", secondary = 'userpasswords')

class UserPasswords(db.Model):
    __tablename__ = 'userpasswords'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    password_id = db.Column(db.Integer, db.ForeignKey("passwords.id"))

db.create_all()
db.session.commit()

def check_auth_reverse(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.is_authenticated == True:
            return redirect(url_for('user_site'))
        else:
            return f(*args, **kwargs)
    return wrap

def send_email(user):
    token = user.get_reset_token()
    mess = Message('Żądanie resetu hasła', sender = 'texterdexter1@gmail.com', recipients = [user.email])
    mess.body = f'''Aby zresetować hasło, kliknj w poniższy link:
{url_for('reset_password', token=token, _external = True)}
Pozdrawiamy!
'''
    mail.send(mess)

class RegisterForm(FlaskForm):
    username = StringField('Username', validators = [InputRequired(message = 'Musisz podać nazwę użytkownika!'),
               Length(min = 3, max = 16, message = 'Nazwa użytkownika musi mieć długość od 3 do 16 znaków!'),
               Regexp("^[A-Za-z0-9_]*$", message = 'Nazwa użytkownika może składać się tylko z liter, cyfr oraz podłogi!')])

    password = PasswordField('Password', validators = [InputRequired(message = 'Musisz podać hasło!'),
               Length(min = 8, max = 40, message = 'Hasło musi składać się conajmniej z 8 znaków i maksymalnie 40!')])
    
    email = StringField('Email', validators = [InputRequired(message = 'Musisz podać adres email!'),
            Length(min = 4, max = 254, message = "Niepoprawna długość adresu email"),
            Email(message = 'Podano niepoprawny email!')])

    submit = SubmitField("Zarejestruj")

    def validate_username(self, username):
        username_check = User.query.filter_by(username = username.data).first()

        if username_check:
            raise ValidationError("Podana nazwa użytkownika jest już zajęta!")

    def validate_email(self, email):
        email_check = User.query.filter_by(email = email.data).first()

        if email_check:
            raise ValidationError("Podany adres email jest już zajęty!")

class LoginForm(FlaskForm):
    username = StringField('Username', validators = [InputRequired(message = 'Musisz podać nazwę użytkownika!'),
               Length(min = 3, max = 16, message = 'Wprowadzono błędne dane!'),
               Regexp("^[A-Za-z0-9_]*$", message = 'Wprowadzono błędne dane!')])

    password = PasswordField('Password', validators = [InputRequired(message = 'Musisz podać hasło!'),
               Length(min = 8, max = 40, message = 'Wprowadzono błędne dane!')])

    submit = SubmitField("Zaloguj")

    def validate_username(self, username):
        user_check = User.query.filter_by(username = username.data).first()

        if not user_check:
            raise ValidationError("Wprowadzono błędne dane!")

    def validate_password(self, password):
        user_check = User.query.filter_by(username = self.username.data).first()

        if user_check:
            tm.sleep(2)
            input_hashed_password, salt_temp = safe_password(password, user_check.salt)
            if user_check.password != input_hashed_password:
                raise ValidationError("Wprowadzono błędne dane!")

class ChangePasswordForm(FlaskForm):
    actual_password = PasswordField('Actual password', validators = [InputRequired(message = 'Musisz podać aktualne hasło!'),
                      Length(min = 8, max = 40, message = 'Podane aktualne hasło ma nieodpowiednią długość!')])

    new_password = PasswordField('New password', validators = [InputRequired(message = 'Musisz podać nowe hasło!'),
                      Length(min = 8, max = 40, message = 'Hasło musi składać się conajmniej z 8 znaków i maksymalnie 40!')])

    new_password_2 = PasswordField('New password again', validators = [InputRequired(message = 'Musisz podać nowe hasło ponownie!'),
                      Length(max = 40)])

    submit = SubmitField('Zmień hasło')

    def validate_new_password_2(self, new_password_2):
        if self.new_password.data != new_password_2.data:
            raise ValidationError("Podane nowe hasło w dwóch polach nie zgadza się, upewnij się, że w obu polach wpisałeś to samo!")

    def validate_actual_password(self, actual_password):
        user_password_check = User.query.filter_by(username = current_user.username).first()
        input_hashed_password, salt_temp = safe_password(actual_password, user_password_check.salt)
        if user_password_check.password != input_hashed_password:
            raise ValidationError("Podane aktualne hasło jest błędne!")

class PasswordManagerForm(FlaskForm):
    password_to_site = PasswordField('Password', validators = [InputRequired(message = 'Musisz podać hasło!')])
    site = StringField('Site', validators = [InputRequired(message = 'Podaj nazwę celu hasła!'),
           Length(min = 2, max = 100, message = 'Wprowadzona nazwa musi składać się z conajmniej 2 znaków i maksymalnie 100!')])

    submit = SubmitField('Zapisz hasło')

class SharePasswordForm(FlaskForm):
    user_to_share_with = StringField('Username', validators = [InputRequired(message = 'Musisz podać nazwę użytkownika!'),
               Length(min = 3, max = 16, message = 'Nazwa użytkownika musi mieć długość od 3 do 16 znaków!'),
               Regexp("^[A-Za-z0-9_]*$", message = 'Nazwa użytkownika może składać się tylko z liter, cyfr oraz podłogi!')])

    submit = SubmitField('Udostępnij!')

    def validate_user_to_share_with(self, user_to_share_with):
        username_check = User.query.filter_by(username = user_to_share_with.data).first()

        if not username_check:
            raise ValidationError("Taki użytkownik nie istnieje!")

class EmailResetPasswordForm(FlaskForm):
    email = StringField('Email', validators = [InputRequired(message = 'Musisz podać adres email!'),
            Length(min = 4, max = 254, message = "Niepoprawna długość adresu email"),
            Email(message = 'Podano niepoprawny email!')])
    
    submit = SubmitField('Zatwierdź')

    def validate_email(self, email):
        email_check = User.query.filter_by(email = email.data).first()

        if email_check:
            flash("Jeśli ten adres email istnieje, wyślemy na niego wiadomość o resecie hasła!")
        elif not email_check:
            raise ValidationError("Jeśli ten adres email istnieje, wyślemy na niego wiadomość o resecie hasła!")

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators = [InputRequired(message = 'Musisz podać hasło!'),
               Length(min = 8, max = 40, message = 'Hasło musi składać się conajmniej z 8 znaków i maksymalnie 40!')])
    
    password_again = PasswordField('PasswordAgain', validators = [InputRequired(message = 'Musisz podać hasło!'),
               Length(min = 8, max = 40, message = 'Hasło musi składać się conajmniej z 8 znaków i maksymalnie 40!')])

    submit = SubmitField('Zresetuj hasło')

    def validate_new_password_2(self, password_again):
        if self.password.data != password_again.data:
            raise ValidationError("Podane nowe hasło w dwóch polach nie zgadza się, upewnij się, że w obu polach wpisałeś to samo!")

@app.route('/')
@check_auth_reverse
def index():
    return render_template('index.html')

@app.route('/login', methods = ['GET', 'POST'])
@check_auth_reverse
def login():
    form = LoginForm()

    if form.validate_on_submit():
        logging_user = User.query.filter_by(username = form.username.data).first()                      
        login_user(logging_user)
        return redirect(url_for('user_site'))

    return render_template('login.html', form = form)

@app.route('/register', methods = ['GET','POST'])
@check_auth_reverse
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password, salt_to_password = safe_password(form.password.data, '1')
        registered_user = User(username = form.username.data,
                             password = hashed_password,
                             email = form.email.data,
                             salt = salt_to_password)

        db.session.add(registered_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form = form)

@app.route('/user_site', methods = ['GET', 'POST'])
@login_required
def user_site():
    return render_template('user_site.html')

@app.route('/changepass', methods = ['GET', 'POST'])
@login_required
def changepass():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        hashed_password, salt_to_password = safe_password(form.new_password.data, '1')
        update_user = User.query.filter_by(username = current_user.username).first()
        update_user.password = hashed_password
        update_user.salt = salt_to_password
        db.session.commit()

        return redirect(url_for('user_site'))

    return render_template('changepass.html', form = form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/password_manager', methods = ['GET', 'POST'])
@login_required
def password_manager():
    form = PasswordManagerForm()

    if form.validate_on_submit():

        sym_pass = symetric_encode(form.password_to_site.data)

        new_password = Passwords(original_owner = current_user.username, password_data = sym_pass, site_data = form.site.data)
        db.session.add(new_password)
        db.session.commit()

        user_add = User.query.filter_by(username = current_user.username).first()
        password_add = Passwords.query.filter_by(password_data = sym_pass).first()

        new_relationship = UserPasswords(user_id = user_add.id, password_id = password_add.id)
        db.session.add(new_relationship)
        db.session.commit()

        return redirect(url_for('password_manager'))

    return render_template('password_manager.html', form = form)

@app.route('/password_sharing/<int:password_to_share>', methods = ['GET', 'POST'])
@login_required
def password_sharing(password_to_share):
    form = SharePasswordForm()

    if form.validate_on_submit():

        user_shared_info = User.query.filter_by(username = form.user_to_share_with.data).first()
        user_share_relationship = UserPasswords(user_id = user_shared_info.id, password_id = password_to_share)

        db.session.add(user_share_relationship)
        db.session.commit()

        return redirect(url_for('passwords_display'))

    return render_template('password_sharing.html', form = form)

@app.route('/passwords_display', methods = ['GET', 'POST'])
@login_required
def passwords_display():
    all_passwords_display = []
    all_passwords = []
    user_temp = User.query.filter_by(username = current_user.username).first()
    user_temp_passwords = UserPasswords.query.filter_by(user_id = user_temp.id)
    for user_temp_passwords_one in user_temp_passwords:
        user_temp_password = Passwords.query.filter_by(id = user_temp_passwords_one.password_id).first()
        decoded_password = symetric_decode(user_temp_password.password_data)
        all_passwords_display.append("Właściciel hasła: " + user_temp_password.original_owner + " Hasło: " + decoded_password + " Hasło do strony: " + user_temp_password.site_data)
        all_passwords.append(user_temp_password)

    return render_template('passwords_display.html', passwords_to_display = zip(all_passwords_display, all_passwords))

@app.route('/email_reset_password', methods = ['GET', 'POST'])
@check_auth_reverse
def email_reset_password():
    form = EmailResetPasswordForm()

    if form.validate_on_submit():
        user_to_send = User.query.filter_by(email = form.email.data).first()
        send_email(user_to_send)
        return redirect(url_for('email_reset_password'))

    return render_template('email_reset_password.html', form = form)

@app.route('/email_reset_password/<token>', methods = ['GET', 'POST'])
@check_auth_reverse
def reset_password(token):
    user = User.verify_reset_token(token)

    if user is None:
        flash('Token jest niepoprawny lub już wygasł!')

        return redirect(url_for('index'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        hashed_password, salt_to_password = safe_password(form.password.data, '1')
        user.password = hashed_password
        user.salt = salt_to_password

        db.session.commit()
        
        return redirect(url_for('login'))

    return render_template('reset_password.html', form = form)

if __name__ == '__main__':
    context = ('server.crt', 'server.key')
    app.run(ssl_context = context)
