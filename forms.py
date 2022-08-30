from flask_wtf import FlaskForm
from jsonschema import ValidationError
from wtforms import StringField,PasswordField,SubmitField,DateTimeField, TextAreaField
from wtforms.validators import Length, EqualTo, Email, DataRequired,Regexp,InputRequired
from app import User
from flask_wtf.file import FileField, FileAllowed
from flask_ckeditor import CKEditorField


class RegisterForm(FlaskForm):       
    username=StringField(label='User Name:', validators=[Length(min=2, max=30),Regexp( "^[A-Za-z][A-Za-z0-9_.]*$",0,"Usernames must have only letters, " "numbers, dots or underscores"), DataRequired()])
    email_address=StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1=PasswordField(label='Password:', validators=[Length(min=8), DataRequired()])
    password2=PasswordField(label='Confirm Password:',validators=[EqualTo('password1'), DataRequired()])
    profile_pic = FileField("Profile Pic")
    date_added=DateTimeField("Date")
    submit=SubmitField(label='Create Account')

    def validate_username(self,username_to_check):
        user=User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')
    def validate_email_address(self,email_address_to_check):
        email_address=User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email_address') 

class LoginForm(FlaskForm):
    username=StringField(label='User Name:', validators=[DataRequired()])
    password=PasswordField(label='Password:', validators=[DataRequired()])
    submit=SubmitField(label='Sing In')



class DeleteUserForm(FlaskForm):
    delete=SubmitField('Delete')


class EmailForm(FlaskForm):
    email_address = StringField('Email', validators=[DataRequired(), Email()])



    
class UserForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	email_address= StringField("Email", validators=[DataRequired()])
	password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
	password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
	profile_pic = FileField("Profile Pic")
	submit = SubmitField("Submit")


# Create A Search Form
class SearchForm(FlaskForm):
	searched = StringField("Searched", validators=[DataRequired()])
	submit = SubmitField("Submit")

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Enter Comment"})
    submit = SubmitField("Add Comment")


class PostForm(FlaskForm):
    title = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Title"})
    post_content = TextAreaField(validators=[InputRequired(), Length(
        min=4, max=1000)], render_kw={"placeholder": "Description"})
    image = FileField(
        "Copertina Articolo", validators=[FileAllowed(["jpg", "jpeg", "png"])]
    )    
    submit = SubmitField("Upload Post")


class UpdatePostForm(FlaskForm):
    title = StringField("Title", validators=[
        InputRequired(), Length(min=4, max=40)])
    post_content = TextAreaField("Description", validators=[
        InputRequired(), Length(min=4, max=1000)])
    submit = SubmitField("Update Post")



class ForgotPasswordForm(FlaskForm):
    email_address = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    submit = SubmitField("Send Reset Email")


class ResetPasswordForm(FlaskForm):
    email_address = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "Password (4 minimum)"})


class ChangePasswordForm(FlaskForm):
    email_address = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    current_password = PasswordField(validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Current Password"})
    new_password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "New Password (4 minimum)"})
    submit = SubmitField("Change Password")


class UserSearchForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Search For Users"})


class MessageForm(FlaskForm):
    message = StringField(validators=[InputRequired(), Length(
        min=4, max=200)], render_kw={"placeholder": "Send A Message"})

