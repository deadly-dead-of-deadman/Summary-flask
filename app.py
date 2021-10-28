import sqlite3
import os
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from UserLogin import UserLogin
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'the random string'

admin_pass = 'iamanadminnow'
admin_pass_hashed = hash(admin_pass)

MAX_CONTENT_LENGTH = 16 * 1024 * 1024
db = SQLAlchemy(app)
login_manager = LoginManager(app)
admin = Admin(app)
USER_ID = 0

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = 'static'


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Поля таблиц БД
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)
    is_admin = db.Column(db.Integer, default=0)

    def __repr__(self):
        return '<Users %r>' % self.id


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    surname = db.Column(db.String(20), nullable=False)
    about = db.Column(db.String(500), nullable=False)
    creator = db.Column(db.Integer, nullable=False)
    avatar = db.Column(db.String(20))

    def __repr__(self):
        return '<Profile %r>' % self.id


@login_manager.user_loader
def load_user(user_id):
    print("load user")
    user_login = UserLogin()
    return user_login.fromDB(user_id, Users)


class SecureModelView(ModelView):
    def is_accessible(self):
        if not current_user.get_id() is None:
            user = Users.query.get(current_user.get_id())
            if user.is_admin == 1:
                return True
        else:
            return False

    def inaccessible_callback(self, name, **kwargs):
        return "Вы не являетеся админом"


admin.add_view(SecureModelView(Users, db.session))
admin.add_view(SecureModelView(Profile, db.session))


# Проверка на роль админа
@app.route('/admin')
@login_required
def admin():
    user = Users.query.get(current_user)
    if user.is_admin == 1:
        return redirect('/admin')
    else:
        return redirect('/')


# Домашняя страница
@app.route('/')
def index():
    profiles = Profile.query.order_by(Profile.id).all()
    user = Users.query.get(current_user.get_id())
    if user:
        is_admin = user.is_admin
    else:
        is_admin = 0
    return render_template('index.html', profiles=profiles, current_user=current_user.get_id(), is_admin=is_admin)


# Логин
@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user = Users.query.filter_by(login=request.form.get("login", False)).first()
        if user and check_password_hash(user.password, request.form.get("password", False)):
            user_login = UserLogin()
            user_login.create(user)
            login_user(user_login)

            # авторизация админа
            admin_password = request.form.get("admin_password")
            if admin_password is not None:
                if hash(admin_password) == admin_pass_hashed:
                    user.is_admin = 1
                    db.session.commit()
        else:
            return "Неверный пароль или логин"
    return render_template('login.html', user=current_user.get_id())


# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


# Регистрация
@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        if len(request.form['login']) > 4 and len(request.form['pass']) > 4 and len(request.form['pass2']) > 4 \
                and request.form['pass'] == request.form['pass2']:
            user_login = request.form['login']
            password = str(generate_password_hash(request.form['pass']))
            user = Users(login=user_login, password=password, is_admin=0)
            try:
                db.session.add(user)
                db.session.commit()
                return redirect('/login')
            except sqlite3.Error as e:
                print("Ошибка добавления пользователя в БД " + str(e))
                return "При создании профиля произошла ошибка"
        else:
            return "Неверно введены поля"
    return render_template('register.html')


# Создание профиля
@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    if current_user.get_id() is None:
        is_admin = 0
    else:
        user = Users.query.get(current_user.get_id())
        is_admin = user.is_admin

    if Profile.query.order_by(Profile.id).all():
        cur_id = (Profile.query.order_by(Profile.id).all())[-1].id
    else:
        cur_id = 1
    if request.method == 'POST':
        name = request.form['name']
        surname = request.form['surname']
        about = request.form['about']
        creator = current_user.get_id()
        portfolio = Profile(name=name, surname=surname, about=about, creator=creator, avatar="default")

        try:
            db.session.add(portfolio)
            db.session.commit()
            return redirect('/')
        except sqlite3.IntegrityError as err:
            db.session.rollback()
            if "UNIQUE constraint failed: user.username" in str(err):
                return False, "error, username already exists (%s)" % name
            elif "FOREIGN KEY constraint failed" in str(err):
                return False, "supplier does not exist"
            else:
                return False, "unknown error adding user"
    else:
        return render_template('profile_creation.html', cur_id=cur_id, is_admin=is_admin)


# Просмотр профиля по ID
@app.route('/profiles/<prof_id>')
def profile_from_id(prof_id):
    if current_user.get_id() is None:
        is_admin = 0
    else:
        user = Users.query.get(current_user.get_id())
        is_admin = user.is_admin

    profile_db = Profile.query.get(prof_id)
    return render_template('profile_from_id.html', profile=profile_db, current_user=current_user.get_id(),
                           is_admin=is_admin)


# Редактирование профиля
@app.route('/edit/<prof_id>', methods=['POST', 'GET'])
@login_required
def edit_profile(prof_id):
    profile_from_db = Profile.query.get(prof_id)
    if profile_from_db.creator == current_user.get_id():
        if request.method == 'GET':
            return render_template('edit_profile.html', profile=profile_from_db, user=current_user.get_id())
        if request.method == 'POST':
            name = request.form['name']
            surname = request.form['surname']
            about = request.form['about']
            creator = current_user.get_id()
            try:
                profile_from_db.name = name
                profile_from_db.surname = surname
                profile_from_db.about = about
                profile_from_db.creator = creator
                db.session.commit()

                return redirect('/profiles/' + prof_id)
            except:
                return "При редактировании портфолио произошла ошибка"
    else:
        return "Нет разрешения на редактирование"


# Редактирование профиля
@app.route('/edit_user/<user>', methods=['POST', 'GET'])
@login_required
def edit_user(user):
    user_from_db = Users.query.get(current_user.get_id())
    if user_from_db.id == current_user.get_id():
        if request.method == 'GET':
            return render_template('edit_user.html')
        if request.method == 'POST':
            new_login = request.form['login']
            old_pass = request.form.get('old_password', False)
            if check_password_hash(user.password, old_pass):
                new_pass = request.form['new_password']
            else:
                return "Неверный пароль"
            try:
                user.login = new_login
                user.password = new_pass

                db.session.commit()

                return redirect('/')
            except:
                return "При редактировании логина или пароля произошла ошибка"
    else:
        return "Нет разрешения на редактирование"


@app.route("/upload/<prof_id>", methods=["POST", "GET"])
@login_required
def upload(prof_id):
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return "Файл не выбран"
        file = request.files['file']
        if file.filename == '':
            return "Файл не выбран"
        if file and allowed_file(file.filename):
            filename = secure_filename(str(prof_id) + ".png")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_from_db = Profile.query.get(prof_id)
            profile_from_db.avatar = filename
            db.session.commit()
            return redirect('/profiles/' + str(prof_id))
    return render_template('upload_img.html')


@app.route("/delete/<prof_id>", methods=["POST", "GET"])
@login_required
def delete_profile(prof_id):
    profile_from_db = Profile.query.get(prof_id)
    if current_user.get_id() == profile_from_db.creator:
        print("ДА")
        try:
            Profile.query.filter(Profile.id == prof_id).delete()
            db.session.commit()
            return redirect('/')
        except:
            return "При удалении профиля произошла ошибка"
    else:
        return redirect("/profiles/ " + str(prof_id))


if __name__ == "__main__":
    app.run(debug=True)
