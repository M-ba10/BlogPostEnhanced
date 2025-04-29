from datetime import date
from flask import Flask, abort, request, render_template, redirect, session, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_required, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ForgotPasswordForm, ResetPasswordForm
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_migrate import Migrate
from flask_babel import Babel, _
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv



# Load environment variables from the .env file
load_dotenv()
print("DB URI from .env:", os.getenv("DB_URI"))


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

secret_key = os.getenv('FLASK_KEY')
#print(f'Secret Key Loaded: {secret_key}')
#db_uri = os.getenv('DB_URI')

app = Flask(__name__)

app.config['SECRET_KEY'] = secret_key

# Configure Flask-Babel for language support
#app.config['LANGUAGES'] = ['en', 'fr', 'ar']  # Supported languages

app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'  # Directory for translations

app.config['LANGUAGES'] = {
    'en': 'English',
    'fr': 'Français',
    'ar': 'العربية'
}

#app.config['BABEL_DEFAULT_LOCALE'] = 'en'  # Default language

babel = Babel(app)



#some_string = _("Welcome to our website")

app.config['EMAIL_USER'] = os.getenv('EMAIL_USER')
app.config['EMAIL_PASS'] = os.getenv('EMAIL_PASS')

ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Create an email confirmation token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

# Send the confirmation email:
def send_confirmation_email(user_email, token):
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = f'Click to confirm your email: <a href="{confirm_url}">{confirm_url}</a>'

    msg = MIMEText(html, 'html')
    msg['Subject'] = 'Please confirm your email'
    msg['From'] = app.config['EMAIL_USER']
    msg['To'] = user_email

    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])
        connection.send_message(msg)

# Languages configuration'''
# Function to get the user's preferred language
def get_locale():
    # 1. Check URL parameter
    if 'lang' in request.args:
        if request.args['lang'] in app.config['LANGUAGES']:
            session['lang'] = request.args['lang']
            return request.args['lang']
    
    # 2. Check session
    if 'lang' in session:
        return session['lang']
    
    # 3. Fallback to browser preference
    return request.accept_languages.best_match(app.config['LANGUAGES'].keys())

# Initialize with locale selector
babel.init_app(app, locale_selector=get_locale)


@app.route('/change_language/<language>')
def change_language(language):
    if language in app.config['LANGUAGES']:
        session['lang'] = language
        # Force refresh the language for current request
        get_locale()
    return redirect(request.referrer or url_for('get_all_posts'))

# Route to change language
'''@app.route('/change_language/<language>')
def change_language(language):
    if language in app.config['LANGUAGES']:
        session['language'] = language
    return redirect(request.referrer or url_for('get_all_posts'))
'''

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# For adding profile images to the comment section
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
#print("SQLAlchemy URI:", app.config['SQLALCHEMY_DATABASE_URI'])

migrate = Migrate(app, db)

#app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///instance/post.db"
'''app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///instance/posts.db")
print("SQLAlchemy URI:", app.config['SQLALCHEMY_DATABASE_URI'])'''

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'posts.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
print("Resolved DB Path:", db_path)



db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # Create reference to the User object. The "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # Parent relationship to the comments
    comments = relationship("Comment", back_populates="parent_post")


# Create a User table for all your registered users
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    # for email confirmation
    confirmed = db.Column(db.Boolean, default=False)
    # For notifications
    receive_notifications = db.Column(db.Boolean, default=True) 
    # For profile images to Do
    #profile_image = db.Column(db.String(250), default="https://www.gravatar.com/avatar/")
    
    
    # This will act like a list of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # Parent relationship: "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")



# Create a table for the comments on the blog posts
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    # Child relationship:"users.id" The users refers to the tablename of the User class.
    # "comments" refers to the comments property in the User class.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    # Child Relationship to the BlogPosts
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# Create the database tables
with app.app_context():
    db.create_all()
    print("Database tables created!")


# Create an admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function

# 5. Add a notification service
def send_new_post_notification(post):
    """Send email notification to all users about new post"""
    try:
        app.logger.info(f"Starting notification for post: {post.title}")
        
        # Get all users who want notifications
        subscribers = User.query.filter_by(receive_notifications=True).all()
        if not subscribers:
            app.logger.info("No subscribers found")
            return

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])
            
            for user in subscribers:
                try:
                    msg = MIMEText(
                        f"Hello {user.name},\n\n"
                        f"New post by {post.author.name}: {post.title}\n"
                        f"Read it here: {url_for('show_post', post_id=post.id, _external=True)}\n\n"
                        "To unsubscribe: {url_for('notification_preferences', _external=True)}",
                        'plain'
                    )
                    msg['Subject'] = f"New Post: {post.title}"
                    msg['From'] = app.config['EMAIL_USER']
                    msg['To'] = user.email
                    
                    server.send_message(msg)
                    app.logger.info(f"Notification sent to {user.email}")
                    
                except Exception as e:
                    app.logger.error(f"Failed to send to {user.email}: {str(e)}")
                    
    except Exception as e:
        app.logger.error(f"Notification system error: {str(e)}")
        raise  # Re-raise if you want to see it in console

#🧾 Add a Search Route in Flask
@app.route("/search", methods=["GET"])
def search_by_author():
    # Get the search query from the request
    # Use request.args.get to get the query parameter from the URL
    # Use strip() to remove any leading or trailing whitespace
    query = request.args.get("query", "").strip()
    # If the query is empty, return an error message
    if not query:
        return render_template("search_results.html", posts=[], query=query, message="Please enter a name to search.")
    # Use ilike for case-insensitive search
    users = User.query.filter(User.name.ilike(f"%{query}%")).all()

    if not users:
        return render_template("search_results.html", posts=[], query=query, message="No authors found matching that name.")

    posts = []
    for user in users:
        posts.extend(user.posts)

    if not posts:
        return render_template("search_results.html", posts=[], query=query, message="Author(s) found, but they haven't written any posts yet.")

    return render_template("search_results.html", posts=posts, query=query)




# Register new users into the User database
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash(_("You've already signed up with that email, log in instead!"))
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
            confirmed=False  # Make sure your User model includes this field
        )
        db.session.add(new_user)
        db.session.commit()
        
         # Generate confirmation token
        token = generate_confirmation_token(new_user.email)

        # Send confirmation email
        send_confirmation_email(new_user.email, token)

        flash(_("A confirmation email has been sent. Please check your inbox."))
        return redirect(url_for("login"))

        # This line will authenticate the user with Flask-Login
        '''login_user(new_user)
        return redirect(url_for("get_all_posts"))'''

    return render_template("register.html", form=form, current_user=current_user)

# 6. Add confirmation route for email confirmation:
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash(_('The confirmation link is invalid or has expired.', 'danger'))
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash(_('Account already confirmed. Please login.', 'info'))
    else:
        user.confirmed = True
        db.session.commit()
        flash(_('Your account has been confirmed!', 'success'))
    return redirect(url_for('login'))


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        # Email doesn't exist
        if not user:
            flash(_("That email does not exist, please try again."))
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash(_('Password incorrect, please try again.'))
            return redirect(url_for('login'))
        
        elif not user.confirmed:
            flash(_("Please confirm your email before logging in."))
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


 # 2. Route: Show Reset Request Page & Send Email
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_confirmation_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)

            # Email setup
            html = f"Click the link to reset your password: <a href='{reset_url}'>{reset_url}</a>"
            msg = MIMEText(html, "html")
            msg["Subject"] = "Reset Your Password"
            msg["From"] = app.config['EMAIL_USER']
            msg["To"] = user.email

            with smtplib.SMTP("smtp.gmail.com", 587) as connection:
                connection.starttls()
                connection.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])
                connection.send_message(msg)

        flash(_("If that email is in our system, a reset link has been sent."))
        return redirect(url_for("login"))

    return render_template("forgot_password.html", form=form, current_user=current_user)

#Route: Handle Token and Show Reset Form    
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash(_("Invalid or expired reset link."))
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        db.session.commit()
        flash(_("Your password has been reset. Please log in."))
        return redirect(url_for("login"))

    return render_template("reset_password.html", form=form, current_user=current_user, token=token)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# Add a POST method to be able to post comments
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    # Add the CommentForm to the route
    comment_form = CommentForm()
    # Only allow logged-in users to comment on posts
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash(_("You need to login or register to comment."))
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


# Use a decorator so only an admin user can create new posts
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
        
        print(f"✅ New post created by {current_user.name}")  # Debug 1

         # Get users who want notifications
        subscribers = User.query.filter_by(receive_notifications=True).all()
        print(f"📢 Found {len(subscribers)} subscribers to notify")  # Debug 2

        # Send notification to all users
        from threading import Thread
        Thread(target=send_new_post_notification, args=(new_post,)).start()
        print("📧 Notifications thread launch!")

        flash(_("New post created successfully and notifications sent!"))
        # Redirect to the main page
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)

# Add notification preference to the user profile
@app.route("/notification_preferences", methods=["GET", "POST"])
@login_required
def notification_preferences():
    if request.method == "POST":
        # Convert checkbox value to boolean
        current_user.receive_notifications = request.form.get('notify') == 'on'
        db.session.commit()
        
        flash(_("Notification preferences updated!"))
        return redirect(url_for("notification_preferences"))
    
    return render_template("notification_preferences.html")


# Use a decorator so only an admin user can edit a post
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
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":

    app.run(debug=True, port=5001)
