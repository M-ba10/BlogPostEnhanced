import secrets
from datetime import date, datetime, timezone
from email.message import EmailMessage
#from time import timezone
from PIL import Image
#from flask_wtf.csrf import csrf_token
from flask_wtf.csrf import CSRFProtect


from sqlalchemy import func
from sqlalchemy.orm import joinedload

from flask import Flask, abort, request, render_template, redirect, session, url_for, flash, request, jsonify

from flask_bootstrap import Bootstrap5

from flask_ckeditor import CKEditor
#from flask_gravatar import Gravatar
import hashlib
from flask_login import UserMixin, login_required, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ForgotPasswordForm, ResetPasswordForm, \
    UpdateAccountForm, ReplyForm, ContactForm
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_migrate import Migrate
from flask_babel import Babel, _
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv



# Load environment variables from the .env file
load_dotenv()




secret_key = os.getenv('FLASK_KEY')
#print(f'Secret Key Loaded: {secret_key}')
#db_uri = os.getenv('DB_URI')

app = Flask(__name__)

'''if os.environ.get('FLASK_ENV') == "development":
    # Local development - use Sqlite from .env
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI', 'sqlite:///instance/posts.db')
    print("DB URI from .env:", os.getenv("DB_URI"))

else:
    # for Deployment- use PostgreSQL from render's database
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', '').replace('postgres://', 'postgresql://')
'''

# 1. EXPLICITLY detect Render's environment
is_render = 'RENDER' in os.environ or 'DATABASE_URL' in os.environ

# 2. FORCE PostgreSQL if on Render
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ['DATABASE_URL'].replace('postgres://', 'postgresql://')
    if is_render
    else 'sqlite:///instance/posts.db'  # Local dev only
)

# 3. VERIFY in logs (check Render's logs for this)
print(f"🔷 Active Database: {'PostgreSQL' if is_render else 'SQLite'}")
print(f"🔷 DB URI: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0]}...")  # Hide password


app.config['SECRET_KEY'] = secret_key

csrf = CSRFProtect(app)

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

# Add these near the top with other configs for profile image
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max


# Disable old CKEditor CDN injection
app.config['CKEDITOR_SERVE_LOCAL'] = False
# Optional: set the CKEditor type (standard, full, basic)
app.config['CKEDITOR_PKG_TYPE'] = 'standard'
ckeditor = CKEditor(app)

bootstrap = Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)



def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_profile_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_fn)

    # Resize image
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn



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

# The account management rout
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm(obj=current_user)  # Pre-populate with current user data

    if form.validate_on_submit():
        # Update name
        current_user.name = form.name.data

        # Handle profile picture upload
        if form.picture.data:
            picture_file = save_profile_picture(form.picture.data)
            if current_user.profile_image and current_user.profile_image != 'default.jpg':
                old_pic = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_image)
                if os.path.exists(old_pic):
                    os.remove(old_pic)
            current_user.profile_image = picture_file

        # Handle password change
        if form.new_password.data:
            if not check_password_hash(current_user.password, form.current_password.data):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('account'))
            current_user.password = generate_password_hash(form.new_password.data)

        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))

    elif request.method == 'GET':
        form.name.data = current_user.name  # Pre-populate on GET request

    return render_template('account.html', form=form, current_user=current_user, get_gravatar_url=get_gravatar_url)


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
'''gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
'''
def get_gravatar_url(email, size=100):
    email = email.strip().lower()
    hash_email = hashlib.md5(email.encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_email}?s={size}&d=retro"


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

class Tag(db.Model):
    __tablename__ = "tags"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    # Relationship
   # posts = db.relationship('BlogPost', secondary=post_tags, backref=db.backref('tags', lazy='dynamic'))

    def __repr__(self):
        return f'<Tag {self.name}>'

# Many-to-many relationship between posts and tags
post_tags = db.Table('post_tags',
                     db.Column('post_id', db.Integer, db.ForeignKey('blog_posts.id'), primary_key=True),
                     db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
                     )

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

    #Updating to include like relationship 4
    likes = relationship("Like", back_populates="post", cascade="all, delete-orphan")

    # Relationship to tags
    tags = db.relationship('Tag', secondary=post_tags, backref=db.backref('posts', lazy='dynamic'))




    # add a propriety to count likes 5
    @property
    def like_count(self):
        return db.session.query(Like).filter_by(post_id=self.id).count()



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
    profile_image = db.Column(db.String(250), nullable=True)

    # for reply notification
    receive_reply_notifications = db.Column(db.Boolean, default=True)
    
    # This will act like a list of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # Parent relationship: "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")

    # added to include like relationship 2
    likes = relationship("Like", back_populates="user", cascade="all, delete-orphan")

    # for tag
    subscribed_tags = db.relationship('Tag', secondary='user_tag_subscriptions', backref='subscribers')


    # method for checking whether the user has liked the post 3
    def has_liked_post(self, post_id):
        return Like.query.filter_by(user_id=self.id, post_id=post_id).first() is not None


# And create this association table
user_tag_subscriptions = db.Table('user_tag_subscriptions',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)

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

    #  for reply functionality
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=True)
    replies = relationship("Comment", back_populates="parent", remote_side=[id], cascade="all, delete-orphan", single_parent=True)
    parent = relationship("Comment", back_populates="replies", remote_side=[parent_id])
    created_at = db.Column(db.DateTime, default=lambda:datetime.now(timezone.utc))

    edited = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime)

####################For like ###################### 1
# Add this to your models section (after the Comment class)
class Like(db.Model):
    __tablename__ = "likes"
    id = db.Column(Integer, primary_key=True)

    # Who liked
    user_id = db.Column(Integer, db.ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="likes")

    # What was liked (post)
    post_id = db.Column(Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    post = relationship("BlogPost", back_populates="likes")

    # When it was liked
    timestamp = db.Column(db.DateTime, default=lambda:datetime.now(timezone.utc))

    # Make sure a user can only like a post once (unique constraint)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)



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


# send like notification 6
# Add this function to handle like notifications
def send_like_notification(post, liker):
    """Send email notification to post author when someone likes their post"""
    try:
        app.logger.info(f"Sending like notification for post: {post.title}")

        # Only notify the author if they want notifications and aren't the one liking
        if post.author.id != liker.id and post.author.receive_notifications:
            try:
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])

                    # Create the notification message
                    msg = MIMEText(
                        f"Hello {post.author.name},\n\n"
                        f"{liker.name} liked your post: {post.title}\n"
                        f"View it here: {url_for('show_post', post_id=post.id, _external=True)}\n\n"
                        f"To manage notifications: {url_for('notification_preferences', _external=True)}",
                        'plain'
                    )
                    msg['Subject'] = f"{liker.name} liked your post: {post.title}"
                    msg['From'] = app.config['EMAIL_USER']
                    msg['To'] = post.author.email

                    server.send_message(msg)
                    app.logger.info(f"Like notification sent to {post.author.email}")

            except Exception as e:
                app.logger.error(f"Failed to send like notification to {post.author.email}: {str(e)}")

    except Exception as e:
        app.logger.error(f"Like notification system error: {str(e)}")


# for reply notifications

def send_reply_notification(reply, parent_comment):
    """Send email notification when someone replies to a comment"""
    try:
        if (parent_comment.comment_author.receive_reply_notifications and
                parent_comment.comment_author.id != reply.comment_author.id):
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])

                msg = MIMEText(
                    _("Hello %(name)s,\n\n"
                      "%(reply_author)s replied to your comment on the post: %(post_title)s\n\n"
                      "Your comment: %(comment_text)s\n"
                      "Reply: %(reply_text)s\n\n"
                      "View the conversation: %(post_url)s\n\n"
                      "To manage notifications: %(prefs_url)s") % {
                        'name': parent_comment.comment_author.name,
                        'reply_author': reply.comment_author.name,
                        'post_title': reply.parent_post.title,
                        'comment_text': parent_comment.text[:100] + ('...' if len(parent_comment.text) > 100 else ''),
                        'reply_text': reply.text[:100] + ('...' if len(reply.text) > 100 else ''),
                        'post_url': url_for('show_post', post_id=reply.parent_post.id, _external=True),
                        'prefs_url': url_for('notification_preferences', _external=True)
                    },
                    'plain'
                )
                msg['Subject'] = _("New reply to your comment on %(title)s") % {'title': reply.parent_post.title}
                msg['From'] = app.config['EMAIL_USER']
                msg['To'] = parent_comment.comment_author.email

                server.send_message(msg)
                app.logger.info(f"Reply notification sent to {parent_comment.comment_author.email}")

    except Exception as e:
        app.logger.error(f"Failed to send reply notification: {str(e)}")

#🧾 Add a Search Route in Flask
@app.route("/search", methods=["GET"])
def search_by_author():
    query = request.args.get("query", "").strip()

    if not query:
        return render_template("search_results.html",
                               posts=[],
                               query=query,
                               message="Please enter a name to search.",
                               get_gravatar_url=get_gravatar_url)

    users = User.query.filter(User.name.ilike(f"%{query}%")).all()

    if not users:
        return render_template("search_results.html",
                               posts=[],
                               query=query,
                               message="No authors found matching that name.",
                               get_gravatar_url=get_gravatar_url)

    # Create a list of posts with author information
    posts_with_authors = []
    for user in users:
        for post in user.posts:
            posts_with_authors.append({
                "id": post.id,
                "title": post.title,
                "subtitle": post.subtitle,
                "date": post.date,
                "author": {
                    "name": user.name,
                    "image": user.profile_image,
                    "email": user.email
                }


            })
            #posts_with_authors.append(post_data)

    if not posts_with_authors:
        return render_template("search_results.html",
                               posts=[],
                               query=query,
                               message="Author(s) found, but they haven't written any posts yet.",
                               get_gravatar_url=get_gravatar_url)

    return render_template("search_results.html",
                           posts=posts_with_authors,
                           query=query,
                           get_gravatar_url=get_gravatar_url)



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
        flash(_('Your account has been confirmed!'))
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

    return render_template("login.html", form=form, current_user=current_user,get_gravatar_url=get_gravatar_url)


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
    return render_template("index.html", all_posts=posts, current_user=current_user, get_gravatar_url=get_gravatar_url)


# Add a POST method to be able to post comments
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)

    # Add the CommentForm to the route
    comment_form = CommentForm()
    reply_form = ReplyForm()

    # User cannot comment on their own post on ly they can reply
    is_author = current_user.is_authenticated and current_user.id == requested_post.author_id
    if comment_form.validate_on_submit():
        if is_author:
            flash(_("As the post author,  you can only reply to existing comment", "warning"))
            return redirect(url_for('show_post', post_id=post_id))


   #Calculate reading time
    reading_time = calculate_reading_time(requested_post.body)

    has_liked = False
    if current_user.is_authenticated:
        # check if user has liked the post and it is not their own post
        has_liked = current_user.has_liked_post(post_id)
       # has_liked = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first() is not None

    ############################# Only allow logged-in users to comment on posts ##############
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
        return redirect(url_for('show_post', post_id=post_id))


    ################## Handle replies ############################
    if reply_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash(_("You need to login to reply."))
            return redirect(url_for("login"))

        # To  allow reply regardless to ownership
        parent_comment_id = request.form.get('parent_comment_id')
        parent_comment = Comment.query.get_or_404(parent_comment_id)

        new_reply = Comment(
            text=reply_form.reply_text.data,
            comment_author=current_user,
            parent_post=requested_post,
            parent_id=parent_comment_id
        )
        db.session.add(new_reply)
        db.session.commit()


        # Send notification in background
        #from threading import Thread
        #Thread(target=send_reply_notification, args=(new_reply, parent_comment)).start()

        send_reply_notification(new_reply, parent_comment)

        flash(_("Your reply has been posted!"))
        return redirect(url_for('show_post',
                                post_id=post_id) + f'#comment-{parent_comment_id}'
                        )

    return render_template("post.html",
                           post=requested_post,
                           current_user=current_user,
                           form=comment_form,
                           reply_form=reply_form,
                           has_liked = has_liked,
                           reading_time=reading_time,
                           is_author=is_author,
                           get_gravatar_url=get_gravatar_url
                           )


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
    return render_template("make-post.html", form=form, current_user=current_user, get_gravatar_url=get_gravatar_url)

# Add notification preference to the user profile
@app.route("/notification_preferences", methods=["GET", "POST"])
@login_required
def notification_preferences():
    if request.method == "POST":
        current_user.receive_notifications = 'notify' in request.form
        current_user.receive_reply_notifications = 'reply_notify' in request.form
        db.session.commit()
        flash(_("Your notification preferences have been updated!"))
        return redirect(url_for('notification_preferences'))

    return render_template("notification_preferences.html",
                           get_gravatar_url=get_gravatar_url)



# rout for like notifications 7
@app.route("/like/<int:post_id>", methods=["POST"])
@login_required
def like_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    app.logger.info(f"Like route called for post {post_id} by user {current_user.id}")

    message = "You can not like your own post"
    if current_user.id == post.author_id:
        return {"status": "error", "message": message}

    # Check if user already liked this post
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()

    if existing_like:
        # User already liked this post, so unlike it
        app.logger.info(f"User {current_user.id} unliking post {post_id}")
        db.session.delete(existing_like)
        db.session.commit()
        like_count = Like.query.filter_by(post_id=post_id).count()
        app.logger.info(f"New like count for post {post_id}: {like_count}")
        return {"status": "unliked", "likes": like_count}
    else:
        # User hasn't liked this post yet, so like it
        app.logger.info(f"User {current_user.id} liking post {post_id}")
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        like_count = Like.query.filter_by(post_id=post_id).count()
        app.logger.info(f"New like count for post {post_id}: {like_count}")

        # Notify post author of the like using threading
        from threading import Thread
        Thread(target=send_like_notification, args=(post, current_user)).start()

        return {"status": "liked", "likes": like_count}


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
    return render_template("make-post.html",
                           form=edit_form,
                           is_edit=True,
                           current_user=current_user,
                           get_gravatar_url=get_gravatar_url)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

# edit comment
@app.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Check if user is authorized to edit this comment
    if comment.author != current_user.id and current_user.id != 1:  # User is not author or admin
        return jsonify({'error': 'Unauthorized'}), 403

    # Get data from request
    data = request.get_json()
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Comment cannot be empty'}), 400

    # Update comment
    comment.text = text
    comment.edited = True
    comment.edited_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        'success': True,
        'text': text,
        'edited_at': comment.edited_at.strftime('%B %d, %Y at %H:%M')
    })

# delete comment
@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Check if user is authorized to delete this comment
    if comment.author != current_user.id and current_user.id != 1:  # User is not author or admin
        return jsonify({'error': 'Unauthorized'}), 403

    # Delete comment
    db.session.delete(comment)
    db.session.commit()

    return jsonify({'success': True})

# reply comment
@app.route('/post/<int:post_id>/reply', methods=['POST'])
@login_required
def reply_comment(post_id):
    if request.method == 'POST':
        # Get form data
        comment_text = request.form.get('reply_text')
        parent_comment_id = request.form.get('parent_comment_id')

        # Validate required fields
        if not comment_text:
            flash('Reply text cannot be empty', 'danger')
            return redirect(url_for('show_post', post_id=post_id))

        # Create new comment
        new_comment = Comment(
            text=comment_text,
            post_id=post_id,
            author_id=current_user.id,
            parent_id=parent_comment_id
        )

        db.session.add(new_comment)
        db.session.commit()

        # Get parent comment for notification
        parent_comment = Comment.query.get(parent_comment_id)
        if parent_comment:
            send_reply_notification(new_comment, parent_comment)

        flash('Your reply has been posted!', 'success')
        return redirect(url_for('show_post', post_id=post_id))




# If you want to implement tags, you'll need a route for them too
@app.route('/tag/<tag_name>')
def tag(tag_name):
    tag = Tag.query.filter_by(name=tag_name).first_or_404()
    posts = tag.posts.order_by(BlogPost.date.desc()).all()
    sort = request.args.get('sort', 'newest')

    is_subscribed = False
    if current_user.is_authenticated:
        is_subscribed = tag in current_user.subscribed_tags

    #sorting logic
    base_query = (db.session.query(BlogPost)
                   .join(post_tags)
                   .join(Tag)
                   .filter(Tag.name == tag_name)
                   .options(joinedload(BlogPost.author)))

    if sort == "oldest":
        posts = base_query.order_by(BlogPost.date.sec()).all()
    elif sort == 'popular':
        posts = sorted(base_query.all(), key=lambda p: p.like_count, reverse=True)
    else:  # newest
        posts = base_query.order_by(BlogPost.date.desc()).all()


    return render_template('tag.html',
                           tag=tag,
                           posts=posts,
                           sort=sort,
                           is_subscribed=is_subscribed,
                           get_gravatar_url=get_gravatar_url,
                           calculate_reading_time=calculate_reading_time)


@app.route('/subscribe_to_tag/<tag_name>', methods=['POST'])
@login_required
def subscribe_to_tag(tag_name):
    tag = Tag.query.filter_by(name=tag_name).first_or_404()

    if tag in current_user.subscribed_tags:
        current_user.subscribed_tags.remove(tag)
        action = 'unsubscribe'
    else:
        current_user.subscribed_tags.append(tag)
        action = 'subscribe'

    db.session.commit()
    return (jsonify({'success': True, 'action': action}))


@app.context_processor
def inject_tags():
    # Get top 20 most used tags with counts
    popular_tags = db.session.query(
        Tag,
        db.func.count(post_tags.c.post_id).label('count')
    ).join(post_tags).group_by(Tag).order_by(db.desc('count')).limit(20).all()

    # Add size classification (for tag cloud)
    tags_with_size = []
    if popular_tags:
        max_count = popular_tags[0][1]
        for tag, count in popular_tags:
            size = min(5, max(1, round(5 * count / max_count)))
            tags_with_size.append({
                'name': tag.name,
                'size': size,
                'count': count
            })

    return {'popular_tags': tags_with_size}

# For reading time, add this to your post route:
def calculate_reading_time(content):
    # Average reading speed: 200 words per minute
    word_count = len(content.split())
    minutes = max(1, round(word_count / 200))
    return minutes

# for contact
def send_email(name, email, phone, message):
    msg = EmailMessage()
    msg['Subject'] = 'New Contact Message from Blog'
    msg['From'] = app.config['EMAIL_USER']
    msg['To'] = app.config['EMAIL_USER']
    msg['Reply-To'] = email # user that sent the mail

    msg.set_content(f"""
    You received a new message from your website contact form:

    Name: {name}
    Email: {email}
    Phone: {phone}
    Message:
    {message}
    """)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        #smtp.starttls()
        smtp.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])
        smtp.send_message(msg)

@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user, get_gravatar_url=get_gravatar_url)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        message = form.message.data

        send_email(name, email, phone, message)
        flash("Message sent successfully!", "success")

        # Redirect to clear the form and avoid resubmission on reload
        return redirect(url_for("contact"))

        #return render_template("contact.html", form=form, msg_sent=True, get_gravatar_url=get_gravatar_url)

    return render_template("contact.html",form=form, current_user=current_user, msg_sent=True, get_gravatar_url=get_gravatar_url)


if __name__ == "__main__":

    app.run(debug=False, port=5001)
