from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, validators
from wtforms.fields.simple import TextAreaField
from wtforms.validators import DataRequired, URL, Email, EqualTo
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField, FileAllowed
from flask_babel import Babel, _


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# Create a form to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


# Create a form to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


# Create a form to add comments
class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")

# Add "Forgot Password" Route and Form
class ForgotPasswordForm(FlaskForm):
    email = StringField("Your email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send reset link")

#Route: Handle Token and Show Reset Form    
class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[EqualTo('password', message='Passwords must match')])
    submit = SubmitField("Reset Password")

#Route: Handle Update account
class UpdateAccountForm(FlaskForm):
    name = StringField('Name', validators=[
        validators.DataRequired(),
        validators.Length(min=2, max=100)
    ])
    picture = FileField('Update Profile Picture', validators=[
        FileAllowed(['jpg', 'jpeg', 'png'], 'Only JPEG or PNG images allowed!')
    ])
    current_password = PasswordField('Current Password', validators=[
        validators.Optional()  # Only required if changing password
    ])
    new_password = PasswordField('New Password', validators=[
        validators.Optional(),
        validators.Length(min=6),
        validators.EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm New Password')
    submit = SubmitField('Update Account')

class ReplyForm(FlaskForm):
    reply_text = TextAreaField(_('Your Reply'), validators=[DataRequired()])
    submit = SubmitField(_('Post Reply'))

# for contact
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone')
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Talk to me')