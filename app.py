from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///books.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Book model
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    available_copies = db.Column(db.Integer, nullable=False)

# Borrow model
class Borrow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    borrow_date = db.Column(db.DateTime, default=datetime.utcnow)
    return_date = db.Column(db.DateTime, nullable=True)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for the home page
@app.route('/')
@login_required
def home():
    return redirect(url_for('dashboard'))

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials'
    return render_template('login.html')

# Route for dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    books = Book.query.all()
    return render_template('dashboard.html', books=books)

# Route to add a book (admin only)
@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    if not current_user.is_admin:
        return 'Unauthorized'
    
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        copies = int(request.form['copies'])
        new_book = Book(title=title, author=author, available_copies=copies)
        db.session.add(new_book)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('add_book.html')

# Route to borrow a book
@app.route('/borrow/<int:book_id>')
@login_required
def borrow_book(book_id):
    book = Book.query.get_or_404(book_id)
    if book.available_copies > 0:
        book.available_copies -= 1
        borrow_record = Borrow(user_id=current_user.id, book_id=book.id)
        db.session.add(borrow_record)
        db.session.commit()
        return redirect(url_for('dashboard'))
    else:
        return 'Book not available'

# Route to return a borrowed book
@app.route('/return/<int:borrow_id>')
@login_required
def return_book(borrow_id):
    borrow_record = Borrow.query.get_or_404(borrow_id)
    if borrow_record.user_id != current_user.id:
        return 'Unauthorized'
    
    if borrow_record.return_date is None:
        borrow_record.return_date = datetime.utcnow()
        borrow_record.book.available_copies += 1
        db.session.commit()
        return redirect(url_for('dashboard'))
    else:
        return 'Book already returned'

# Route to logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Create the database (only needed once)
@app.before_first_request
def create_tables():
    db.create_all()

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
