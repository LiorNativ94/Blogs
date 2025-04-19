from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, CreateUserForm, CommentForm, LoginForm

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex()
ckeditor = CKEditor(app)
Bootstrap5(app)
app.config['CKEDITOR_PKG_TYPE'] = 'full'

# TODO: Configure Flask-Login
#Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # One blog post has one author
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    author: Mapped["User"] = relationship("User", back_populates="posts")
    # One blog post has many comments
    comments: Mapped[list["Comment"]] = relationship('Comment', back_populates="post", cascade="all, delete-orphan")

# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    # One user has many blog posts
    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
    # One user has many comments
    comments: Mapped[list["Comment"]] = relationship('Comment', back_populates="comment_author", cascade="all, delete-orphan")

# TODO: Create a Comment Table for all comments.
class Comment(db.Model):
    __tablename__ = 'comments'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    # One comment has one author
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    comment_author: Mapped["User"] = relationship("User", back_populates="comments")
    # One comment belongs to one blog post
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()

#Admin Only function
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods = ['POST','GET'])
def register():
    form = CreateUserForm()
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar()
        if user:
            flash("You've already signed up with that email, Log in instead")
            return redirect(url_for('login'))
        else:
            try:
                new_user = User(
                    name = request.form.get('name'),
                    email = request.form.get('email'),
                    password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('get_all_posts'))
            except Exception as e:
                return {'Error': f'this is the error - {e}'}
    return render_template("register.html", form=form, logged_in = current_user.is_authenticated)

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        entered_email = request.form.get('email')
        entered_password = request.form.get('password')
        user = db.session.execute(db.select(User).filter_by(email=entered_email)).scalar()
        if not user:
            flash('That email doesnt not exist. Please try again.')
            return redirect('login')
        elif not check_password_hash(user.password,entered_password):
            flash('Password, incorrect, please try again')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, logged_in = current_user.is_authenticated)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, logged_in = current_user.is_authenticated)

# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods = ['POST','GET'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.body.data,
            comment_author = current_user,
            post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        flash("Comment added!")
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html",form=form, post=requested_post, logged_in = current_user.is_authenticated)

@app.route('/delete-comment/<int:comment_id>', methods=['POST', 'GET'])
@login_required
def delete_comment(comment_id):
    print('check')
    comment = db.get_or_404(Comment,comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash("comment deleted")
    return redirect(url_for('show_post', post_id=comment.post_id))


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in = current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in = current_user.is_authenticated)


@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html", logged_in = current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
