from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, url_for, redirect, flash, request, session
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_admin import Admin, expose
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import InputRequired
from werkzeug.utils import secure_filename
from flask_admin.form import Select2Widget
import random
from datetime import datetime


app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
app.config['SECRET_KEY'] = 'tvvievf87ydvkoy'
db = SQLAlchemy(app)
admin = Admin(app, template_mode='bootstrap4', name='Школьный журнал')
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
admin._menu = admin._menu[1:]


#Для request.user
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class AdminView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin()
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))
    
    form_extra_fields = {
        'role': SelectField(
            'Role',
            choices=[
                ('admin', 'Admin'), 
                ('user', 'User'), 
                ('moderator', 'Moderator'),
                ('editor', 'Editor'), 
            ],
            widget=Select2Widget(),
            description='Choose user role'
        )
    }


#Формы регистрации, админ -----------------------------------------------------
class Registerform(FlaskForm):
    """Регистрация пользоватля """
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})
    captcha = StringField('Введите число', validators=[InputRequired(message="Это поле обязательно для заполнения")])
    submit = SubmitField('Зарегистрироваться')
    def validate_username(self,username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            flash('Это имя пользователя уже существует. Пожалуйста, выберите другой вариант.', 'error')
            raise ValidationError('Это имя пользователя уже существует. Пожалуйста, выберите другой вариант.')


class Loginform(FlaskForm):
	"""Вход пользователя """
	username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя"})
	password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})
	submit = SubmitField('Войти')


#Модели --------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=True) 
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
	
    def is_admin(self):
        return self.role == 'admin'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    students = db.relationship('Student', backref='group')
    

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    marks = db.relationship('Mark', backref='student')


class Mark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    value = db.Column(db.Integer, nullable=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'))


admin.add_view(AdminView(User, db.session))
admin.add_view(AdminView(Group, db.session))
admin.add_view(AdminView(Student, db.session))
admin.add_view(AdminView(Mark, db.session))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registerform()

    if request.method == 'GET':
        num = random.randint(1000, 9999)
        session['captcha'] = str(num)
    else:
        num = session.get('captcha')

    if form.validate_on_submit():
        if form.captcha.data != session.get('captcha'):
            flash('Неправильная капча. Попробуйте еще раз.', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password) 
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form, num=num)


@app.route('/journal')
@login_required
def journal():
    groups = Group.query.all()
    selected_group_id = request.args.get('group')
    students = []

    if selected_group_id and selected_group_id != "all":
        selected_group_id = int(selected_group_id)
        students = Student.query.filter_by(group_id=selected_group_id).all()
    else:
        students = Student.query.all()

    dates_query = db.session.query(Mark.date).distinct().order_by(Mark.date)
    dates = [date_obj.date for date_obj in dates_query]

    return render_template('journal.html', groups=groups, students=students, dates=dates, selected_group_id=selected_group_id)


@app.route('/add_student', methods=['POST'])
def add_student():
    if request.method == 'POST':
        student_name = request.form.get('student_name')
        group_id = request.form.get('group_id')
        
        if not student_name or not group_id:
            flash('Необходимо заполнить все поля.', 'error')
            return redirect(url_for('journal')) 

        try:
            new_student = Student(name=student_name, group_id=group_id)
            db.session.add(new_student)
            db.session.commit()
            flash('Ученик успешно добавлен.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Произошла ошибка при добавлении ученика.', 'error')
        
        return redirect(url_for('journal')) 

    return redirect(url_for('journal')) 


@app.route('/remove_student', methods=['POST'])
def remove_student():
    student_id = request.form.get('student_id')
    if student_id:
        student = Student.query.get(student_id)
        if student:
            db.session.delete(student)
            db.session.commit()
            flash('Ученик успешно удален.', 'success')
        else:
            flash('Ученик не найден.', 'error')
    else:
        flash('ID ученика не предоставлен.', 'error')

    return redirect(url_for('journal'))


@app.route('/add_date', methods=['POST'])
def add_date():
    new_date_str = request.form.get('new_date')
    if new_date_str:
        new_date = datetime.strptime(new_date_str, '%Y-%m-%d').date()

        students = Student.query.all()
        for student in students:
            new_mark = Mark(date=new_date, student_id=student.id)
            db.session.add(new_mark)
        db.session.commit()
        flash('Дата успешно добавлена', 'success')
    else:
        flash('Необходимо выбрать дату', 'error')
    
    return redirect(url_for('journal'))


@app.route('/add_mark', methods=['POST'])
def add_mark():
    student_id = request.form.get('student_id')
    date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
    value = request.form.get('value')

    if not student_id or not date or not value:
        flash('Необходимо заполнить все поля формы.', 'error')
        return redirect(url_for('journal'))

    existing_mark = Mark.query.filter_by(student_id=student_id, date=date).first()
    if existing_mark:
        existing_mark.value = value
        flash('Оценка добавлена.', 'success')
    else:
        new_mark = Mark(student_id=student_id, date=date, value=value)
        db.session.add(new_mark)
        flash('Оценка добавлена.', 'success')

    db.session.commit()
    return redirect(url_for('journal'))


if __name__ == '__main__':
    app.run(debug=True)
