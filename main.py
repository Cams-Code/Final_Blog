from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, ForeignKey, String, Text
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
login_manager = LoginManager()
login_manager.init_app(app)
ckeditor = CKEditor(app)
Bootstrap(app)
Base = declarative_base()

# Initialize gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True)
    full_name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    password = Column(String(250), nullable=False)
    # relationship with BlogPost table
    posts = relationship("BlogPost", back_populates="author")
    # relationship with Comments table
    comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String, nullable=False)

    # Creates foreign key.
    author_id = Column(Integer, ForeignKey("Users.id"))
    # Reference to the User object, "posts" refers to posts property in User class
    author = relationship("User", back_populates="posts")

    # Relationship with Comment Table
    post_comments = relationship("Comment", back_populates="related_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    text = Column(Text, nullable=False)

    # relationship with User table
    commenter_id = Column(Integer, ForeignKey("Users.id"))
    commenter = relationship("User", back_populates="comments")

    # relationship with BlogPost table
    post_id = Column(Integer, ForeignKey("blog_posts.id"))
    related_post = relationship("BlogPost", back_populates="post_comments")

db.create_all()


# user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user_id = current_user.id
        except:
            user_id = 0

        if user_id == 1:
            return f(*args, **kwargs)
        else:
            return abort(403)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_name = form.name.data
        user_password = form.password.data
        user_email = form.email.data
        if User.query.filter_by(email=user_email).first():
            flash("That email already exists, try login.")
            return redirect(url_for("login"))
        else:

            add_user = User(
                full_name=user_name,
                email=user_email,
                password=generate_password_hash(user_password, method="pbkdf2:sha256", salt_length=8)
            )
            db.session.add(add_user)
            db.session.commit()

            user = User.query.filter_by(email=user_email).first()
            login_user(user)

            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if request.method == "POST":
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        try:
            check_password_hash(user.password, password)
        except AttributeError:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))
        else:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect Password, please try again.")
                return redirect(url_for("login"))

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()

    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.comment.data,
                commenter_id=current_user.id,
                post_id=requested_post.id
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)
        else:
            flash("You need to be logged in to add a comment.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>", methods=["GET", "POST"])
@admin_only
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
