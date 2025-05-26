import secrets
from datetime import date, datetime, timezone
from email.message import EmailMessage
from PIL import Image
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from flask import Flask, abort, request, render_template, redirect, session, url_for, flash, jsonify
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
import hashlib
from flask_login import UserMixin, login_required, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ForgotPasswordForm, ResetPasswordForm, \
    UpdateAccountForm, ReplyForm, ContactForm
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_migrate import Migrate
from flask_babel import Babel, _
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address




# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_KEY')

# Database Configuration - SQLite version
'''
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance/posts.db')

# Ensure the instance directory exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
'''

#################################################################db##########################################
# Database Configuration
if os.environ.get('RENDER'):  # Production on Render
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace(
        'postgres://', 'postgresql://'  # Required for SQLAlchemy 1.4+
    )
else:  # Local development
    # SQLite configuration
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(basedir, 'instance', 'site.db')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,  # Optional but recommended for PostgreSQL
    'pool_recycle': 300,    # Recycle connections every 5 minutes
}

'''def init_db():
    with app.app_context():
        db.create_all()'''
######################################################### end#######################################


# Initialize extensions
csrf = CSRFProtect(app)
bootstrap = Bootstrap5(app)
ckeditor = CKEditor(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'





# Initialize SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)


def get_weather(location="London"):
    try:
        api_key = os.getenv('OPENWEATHER_API_KEY')
        if not api_key:
            app.logger.error("OpenWeather API key missing!")
            return {'error': 'Weather service unavailable'}

        response = requests.get(
            'https://api.openweathermap.org/data/2.5/weather',
            params={
                'q': location,
                'appid': api_key,
                'units': 'metric',
                'lang': get_locale()
            },
            timeout=5
        )

        # More specific HTTP error handling
        if response.status_code == 401:
            app.logger.error("Invalid OpenWeather API Key")
            return {'error': 'Weather service configuration error'}
        elif response.status_code == 404:
            return {'error': _('City not found. Please try another location.')}
        elif response.status_code == 429:
            return {'error': _('Too many requests. Please try again later.')}

        response.raise_for_status()
        data = response.json()

        # Validate response structure
        if not all(key in data for key in ['main', 'weather', 'sys']):
            app.logger.error(f"Malformed API response: {data}")
            return {'error': _('Invalid weather data received')}

        return {
            'temp': data['main']['temp'],
            'description': data['weather'][0]['description'].capitalize(),
            'icon': data['weather'][0]['icon'],
            'city': data['name'],
            'country': data['sys'].get('country', ''),
            'humidity': data['main']['humidity'],
            'wind_speed': data['wind']['speed'],
            'feels_like': data['main']['feels_like']
        }

    except requests.exceptions.Timeout:
        app.logger.warning("Weather API timeout")
        return {'error': _('Weather service timeout. Please try again later.')}
    except Exception as e:
        app.logger.error(f"Weather API critical error: {str(e)}")
        return {'error': _('Weather service unavailable')}


############################# WEATHER service ###############################
def get_weather_by_coords(lat, lon):
    try:
        response = requests.get(
            'https://api.openweathermap.org/data/2.5/weather',
            params={
                'lat': lat,
                'lon': lon,
                'appid': os.getenv('OPENWEATHER_API_KEY'),
                'units': 'metric',
                'lang': get_locale()
            },
            timeout=5
        )

        if response.status_code == 404:
            return {'error': _('Location not found')}

        response.raise_for_status()
        data = response.json()

        return {
            'temp': data['main']['temp'],
            'description': data['weather'][0]['description'].capitalize(),
            'icon': data['weather'][0]['icon'],
            'city': data['name'],
            'country': data['sys'].get('country', ''),
            'humidity': data['main']['humidity'],
            'wind_speed': data['wind']['speed'],
            'feels_like': data['main']['feels_like'],
            'by_location': True  # Flag to show it's from geolocation
        }

    except Exception as e:
        app.logger.error(f"Coord weather error: {str(e)}")
        return {'error': str(e)}





limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
@app.route('/api/weather', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def weather_api():
    try:
        app.logger.info(f'Weather API called with params: {request.args}')

        if request.method == 'POST':
            city = request.form.get('city')
            if city:
                session['weather_city'] = city
                session.modified = True  # Ensure session is saved
            return jsonify({"success": True})

        # Try coordinates first
        lat = request.args.get('lat')
        lon = request.args.get('lon')
        if lat and lon:
            try:
                weather = get_weather_by_coords(lat, lon)
                if 'error' not in weather:
                    return jsonify(weather)
                app.logger.warning(f"Coordinate weather error: {weather['error']}")
            except Exception as e:
                app.logger.error(f"Coordinate lookup failed: {str(e)}")

        # Fallback to city
        city = request.args.get('city') or session.get('weather_city') or 'London'
        weather = get_weather(city)

        if 'error' in weather:
            app.logger.warning(f"Weather lookup failed for {city}: {weather['error']}")
            return jsonify({'error': weather['error']}), 400

        return jsonify(weather)

    except Exception as e:
        app.logger.critical(f"Weather API endpoint crashed: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500




@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))




# Configure Babel
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
app.config['LANGUAGES'] = {
    'en': 'English',
    'fr': 'Français',
    'ar': 'العربية'
}


def get_locale():
    # 1. Check URL parameter
    if 'lang' in request.args:
        lang = request.args['lang']
        if lang in app.config['LANGUAGES']:
            session['lang'] = lang
            return lang

    # 2. Check session
    if 'lang' in session:
        return session['lang']

    # 3. Fallback to browser preference
    return request.accept_languages.best_match(app.config['LANGUAGES'].keys())

babel = Babel(app)
babel.init_app(app, locale_selector=get_locale)

# Email configuration
app.config['EMAIL_USER'] = os.getenv('EMAIL_USER')
app.config['EMAIL_PASS'] = os.getenv('EMAIL_PASS')

# Profile image configuration
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max


# Models
class Base(DeclarativeBase):
    pass


# Association table for post tags
post_tags = db.Table('post_tags',
                     db.Column('post_id', db.Integer, db.ForeignKey('blog_posts.id'), primary_key=True),
                     db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
                     )

# Association table for user tag subscriptions
user_tag_subscriptions = db.Table('user_tag_subscriptions',
                                  db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
                                  db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
                                  )


class Tag(db.Model):
    __tablename__ = "tags"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def _repr_(self):
        return f'<Tag {self.name}>'


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")
    likes = relationship("Like", back_populates="post", cascade="all, delete-orphan")
    tags = relationship('Tag', secondary=post_tags, backref=db.backref('posts', lazy='dynamic'))

    @property
    def like_count(self):
        return db.session.query(Like).filter_by(post_id=self.id).count()




class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    confirmed = db.Column(db.Boolean, default=False)
    receive_notifications = db.Column(db.Boolean, default=True)
    profile_image = db.Column(db.String(250), nullable=True)
    receive_reply_notifications = db.Column(db.Boolean, default=True)
    posts = relationship("BlogPost", back_populates="author", lazy='dynamic')
    comments = relationship("Comment", back_populates="comment_author")
    likes = relationship("Like", back_populates="user", cascade="all, delete-orphan")
    subscribed_tags = db.relationship('Tag', secondary='user_tag_subscriptions', backref='subscribers')

    def has_liked_post(self, post_id):
        return Like.query.filter_by(user_id=self.id, post_id=post_id).first() is not None


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=True)
    replies = relationship("Comment", back_populates="parent", remote_side=[id], cascade="all, delete-orphan",
                           single_parent=True)
    parent = relationship("Comment", back_populates="replies", remote_side=[parent_id])
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    edited = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime)


class Like(db.Model):
    __tablename__ = "likes"
    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, db.ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="likes")
    post_id = db.Column(Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    post = relationship("BlogPost", back_populates="likes")
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)

###################################################

def init_db():
    with app.app_context():
        try:
            db.create_all()
            print(f"✅ Database (and tables) ensured at {app.config['SQLALCHEMY_DATABASE_URI']}")
        except Exception as e:
            print(f"❌ Database operation failed: {str(e)}")

init_db()

###################################################



# Helper Functions
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_profile_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


def get_gravatar_url(email, size=100):
    email = email.strip().lower()
    hash_email = hashlib.md5(email.encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_email}?s={size}&d=retro"


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')


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


def calculate_reading_time(content):
    word_count = len(content.split())
    minutes = max(1, round(word_count / 200))
    return minutes


def send_email(name, email, phone, message):
    msg = EmailMessage()
    msg['Subject'] = 'New Contact Message from Blog'
    msg['From'] = app.config['EMAIL_USER']
    msg['To'] = app.config['EMAIL_USER']
    msg['Reply-To'] = email

    msg.set_content(f"""
    You received a new message from your website contact form:

    Name: {name}
    Email: {email}
    Phone: {phone}
    Message:
    {message}
    """)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])
        smtp.send_message(msg)

# for reply notifications

def send_reply_notification(reply, parent_comment):
    """Send email notification when someone replies to a comment"""
    with app.app_context():
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


# 5. Add a notification service
def send_new_post_notification(post):
    """Send email notification to all users about new post"""
    with app.app_context():
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
    with app.app_context():
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



# Decorators
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


######################################### Routes #################################
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

#################################language setup
@app.route('/change_language/<language>')
def change_language(language):
    if language in app.config['LANGUAGES']:
        session['lang'] = language
        # Force refresh the language for current request
        get_locale()
    return redirect(request.referrer or url_for('get_all_posts'))

@app.context_processor
def inject_template_methods():
    return {
        'get_locale': get_locale,
        'current_language': session.get('lang', 'en')
    }




@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
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
            confirmed=False
        )
        db.session.add(new_user)
        db.session.commit()

        token = generate_confirmation_token(new_user.email)
        send_confirmation_email(new_user.email, token)

        flash(_("A confirmation email has been sent. Please check your inbox."))
        return redirect(url_for("login"))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if not user:
            flash(_("That email does not exist, please try again."))
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash(_('Password incorrect, please try again.'))
            return redirect(url_for('login'))
        elif not user.confirmed:
            flash(_("Please confirm your email before logging in."))
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user, get_gravatar_url=get_gravatar_url)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    #result = db.session.execute(db.select(BlogPost))
   # posts = result.scalars().all()
    # Eager load the author information with joinedload
    posts = BlogPost.query.options(joinedload(BlogPost.author)).order_by(BlogPost.date.desc()).all()
    return render_template("index.html", all_posts=posts, current_user=current_user, get_gravatar_url=get_gravatar_url)

# Add a POST method to be able to post comments
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    reply_form = ReplyForm()

    # Calculate reading time
    reading_time = calculate_reading_time(requested_post.body)

    # Check if user has liked the post
    has_liked = False
    if current_user.is_authenticated:
        has_liked = Like.query.filter_by(
            user_id=current_user.id,
            post_id=post_id
        ).first() is not None

    # Check if current user is the author
    is_author = current_user.is_authenticated and current_user.id == requested_post.author_id

    # Handle comment submission
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash(_("You need to login or register to comment."))
            return redirect(url_for("login"))

        if is_author:
            flash(_("As the post author, you can only reply to existing comments"), "warning")
            return redirect(url_for('show_post', post_id=post_id))

        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))

    # Handle reply submission
    if reply_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash(_("You need to login to reply."))
            return redirect(url_for("login"))

        parent_comment_id = request.form.get('parent_comment_id')
        parent_comment = db.get_or_404(Comment, parent_comment_id)

        new_reply = Comment(
            text=reply_form.reply_text.data,
            comment_author=current_user,
            parent_post=requested_post,  # Use the relationship
            parent_id=parent_comment_id
        )
        db.session.add(new_reply)
        db.session.commit()

        send_reply_notification(new_reply, parent_comment)
        flash(_("Your reply has been posted!"))
        return redirect(url_for('show_post', post_id=post_id, _anchor=f'comment-{new_reply.id}'))

    return render_template("post.html",
                           post=requested_post,
                           current_user=current_user,
                           form=comment_form,
                           reply_form=reply_form,
                           has_liked=has_liked,
                           reading_time=reading_time,
                           is_author=is_author,
                           get_gravatar_url=get_gravatar_url
                           )


# Create new posts
@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,  # This ensures proper ownership
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()

        ctx = app.app_context()
        ctx.push()
        # Send notifications
        from threading import Thread
        #subscribers = User.query.filter_by(receive_notifications=True).all()
        Thread(target=send_new_post_notification, args=(new_post,)).start()

        ctx.pop()

        flash(_("New post created successfully!"))
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user, get_gravatar_url=get_gravatar_url)


# Edit posts
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)

    # Only allow author or admin (id=1) to edit
    if current_user.id != post.author_id and current_user.id != 1:
        abort(403)

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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html",
                           form=edit_form,
                           is_edit=True,
                           current_user=current_user,
                           get_gravatar_url=get_gravatar_url
                           )


# Delete posts
@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)

    # Only allow author or admin (id=1) to delete
    if current_user.id != post_to_delete.author_id and current_user.id != 1:
        abort(403)

    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



# rout for like notifications 7
@app.route("/like/<int:post_id>", methods=["POST"])
@login_required
def like_post(post_id):
    post = db.get_or_404(BlogPost, post_id)

    if current_user.id == post.author_id:
        return jsonify({"status": "error", "message": "You cannot like your own post"}), 400

    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()

    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        like_count = post.like_count
        return jsonify({"status": "unliked", "likes": like_count})
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        like_count = post.like_count

        # Send notification
        send_like_notification(post, current_user)

        return jsonify({"status": "liked", "likes": like_count})


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


@app.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)

    # Only allow comment author or admin to edit
    if comment.comment_author.id != current_user.id and current_user.id != 1:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400

    new_text = data['text'].strip()
    if not new_text:
        return jsonify({'success': False, 'error': 'Comment cannot be empty'}), 400

    comment.text = new_text
    comment.edited = True
    comment.edited_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        'success': True,
        'text': new_text,
        'edited_at': comment.edited_at.strftime('%B %d, %Y at %H:%M')
    })


@app.route('/post/<int:post_id>/reply', methods=['POST'])
@login_required
def reply_comment(post_id):
    try:
        # Validate input
        if not request.form.get('reply_text') or not request.form.get('parent_comment_id'):
            return jsonify({
                'success': False,
                'message': 'Reply text and parent comment ID are required'
            }), 400

        # Get parent comment and post with error handling
        try:
            parent_comment = db.session.get(Comment, request.form['parent_comment_id'])
            post = db.session.get(BlogPost, post_id)

            if not parent_comment or not post:
                return jsonify({
                    'success': False,
                    'message': 'Comment or post not found'
                }), 404
        except Exception as e:
            return jsonify({
                'success': False,
                'message': 'Error retrieving comment or post'
            }), 500

        # Create the reply
        new_reply = Comment(
            text=request.form['reply_text'],
            comment_author=current_user,
            parent_post=post,
            parent_id=parent_comment.id
        )

        db.session.add(new_reply)
        db.session.commit()

        # Send notification (in background if possible)
        try:
            send_reply_notification(new_reply, parent_comment)
        except Exception as e:
            app.logger.error(f"Failed to send notification: {str(e)}")

        # Return success response
        return jsonify({
            'success': True,
            'reply': {
                'id': new_reply.id,
                'text': new_reply.text,
                'author_name': current_user.name,
                'author_image': (url_for('static', filename='profile_pics/' + current_user.profile_image)
                                 if current_user.profile_image
                                 else get_gravatar_url(current_user.email, 35)),
                'created_at': new_reply.created_at.strftime('%B %d, %Y at %H:%M'),
                'is_author': True
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating reply: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)

    # Only allow comment author or admin to delete
    if comment.comment_author.id != current_user.id and current_user.id != 1:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    db.session.delete(comment)
    db.session.commit()

    return jsonify({'success': True})


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

# ... (include all other routes from your original code)

if __name__ == '__main__':

    #init_db()
    with app.app_context():
        db.create_all()

    app.run(debug=False, port=5001)