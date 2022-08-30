#from crypt import methods
import re
import bcrypt
from flask import Flask, render_template, redirect, url_for, flash, request,jsonify,abort,session, Blueprint
import flask
from flask_sqlalchemy import SQLAlchemy
import datetime
from flask_mail import Mail,Message
from itsdangerous import NoneAlgorithm
import forms
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required,login_user,logout_user,UserMixin,current_user
from authlib.integrations.flask_client import OAuth
import os
from threading import Thread
from flask_mail import Message,Mail
import uuid as uuid
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from flask_simple_serializer.serializers import Serializer
from sqlalchemy import func, desc
from flask_ckeditor import CKEditor
import secrets
import hashlib
from PIL import Image
from flask_paginate import Pagination
from flask_socketio import SocketIO, send, emit, join_room
from flask import session
import random  
import string
import cloudinary as Cloud
from cloudinary import uploader
from cloudinary.utils import cloudinary_url
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:1111@localhost:5432/deneme_db'
app.config['SECRET_KEY']='1afc337aa889577aba3fbad1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'xxxx@gmail.com'
app.config['MAIL_PASSWORD'] = '******'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'


UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

mail = Mail(app)
db= SQLAlchemy(app)
bc=Bcrypt(app)
login_manager= LoginManager(app)
login_manager.login_view= "Login_page"
oauth = OAuth(app)
migrate = Migrate(app, db)
socketio = SocketIO(app,logger=True, engineio_logger=True)
ckeditor = CKEditor(app)

tags = db.Table(
    'post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.context_processor
def base():
	form = forms.SearchForm()
	return dict(form=form)



@app.shell_context_processor
def make_shell_context():
    return dict(app=app, db=db, User=User, Post=Post, Tag=Tag, migrate=migrate)

    

class User(db.Model,UserMixin): 
  id = db.Column(db.Integer, primary_key=True,autoincrement=True) #autoincriement==Used as more than one primarykey in more than one table in relational tables
  username = db.Column(db.VARCHAR(30), nullable=False,unique=True)
  email_address= db.Column(db.VARCHAR(50), nullable=False,unique=True)
  password_hash= db.Column(db.VARCHAR(60),nullable=False)
  date_added = db.Column(db.DateTime(), default=datetime.datetime.now)
  profile_pic = db.Column(db.VARCHAR(100), nullable=True)
  posts = db.relationship('Post', back_populates='author')
  liker = db.relationship('Like', backref='liker', lazy='dynamic')
  followed = db.relationship(
        'Follower', backref='followed', foreign_keys='Follower.followed_id', lazy='dynamic')
  follower = db.relationship(
        'Follower', backref='follower', foreign_keys='Follower.follower_id', lazy='dynamic')
  sender = db.relationship('Message', backref='sender',
                             foreign_keys='Message.sender_id', lazy='dynamic')
  receiver = db.relationship('Message', backref='receiver',
                               foreign_keys='Message.receiver_id', lazy='dynamic')
  bio_content = db.Column(db.VARCHAR(100), nullable=True)
  verified = db.Column(db.Boolean(), default=False)
  access_token = db.Column(db.Text())
  commenter = db.relationship('Comment', backref='commenter', lazy='dynamic')


  def has_liked_post(self, post):
        return Like.query.filter(
            Like.liker_id == self.id,
            Like.liked_id == post.id).count() > 0

  def has_followed_user(self, user):
        return Follower.query.filter(
            Follower.follower_id == self.id,
            Follower.followed_id == user.id).count() > 0

  def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

  @staticmethod
  def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

  @property
  def password(self):
    return self.password
  @password.setter
  def password(self,plain_text_password):
    self.password_hash = bc.generate_password_hash(plain_text_password).decode('utf-8')


    def __init__(self, title):
        self.title = title

    def __repr__(self):
        return "<Tag '{}'>".format(self.title)

  
  def check_password_correction(self,attempted_password): 
      return bc.check_password_hash(self.password_hash, attempted_password)
      

  def __init__(self, username,email_address,password,date_added,profile_pic, ):
        self.username = username
        self.email_address= email_address
        self.password=password
        self.date_added=date_added
        self.profile_pic=profile_pic

      

  def __repr__(self):
        # formats what is shown in the shell when print is
        # called on it
        return '<User {}>'.format(self.username)


class Post(db.Model,UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    post_content = db.Column(db.Text(), nullable=False)
    publish_date = db.Column(db.DateTime(), default=datetime.datetime.now)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    likes = db.relationship('Like', backref='liked', lazy='dynamic')
    author = db.relationship('User', back_populates='posts')
    ımage = db.Column(db.Text())
    comments = db.relationship(
        'Comment',
        backref='comments',
        lazy='dynamic'
    )
    tags = db.relationship(
        'Tag',
        secondary=tags,
        backref=db.backref('posts', lazy='dynamic')
    )

    def __init__(self, title,post_content,author,image):
        self.title = title
        self.post_content=post_content
        self.author=author
        self.image=image
        

    def __repr__(self):
        return "<Post '{}'>".format(self.title)



class Comment(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    commenter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text(), nullable=False)
    date = db.Column(db.DateTime(), default=datetime.datetime.now)
    post_id = db.Column(db.Integer(), db.ForeignKey('post.id'))

    def __repr__(self):
        return "<Comment '{}'>".format(self.text[:15])

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    liked_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    liker_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Follower(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))



class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(), nullable=False)
    message = db.Column(db.String(), nullable=False)
    time = db.Column(db.String(), nullable=False)
    message_time = db.Column(
        db.DateTime())
    read = db.Column(db.Boolean())
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Tag(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False, unique=True)

def sidebar_data():
    recent = Post.query.order_by(Post.publish_date.desc()).limit(5).all()
    top_tags = db.session.query(
        Tag, func.count(tags.c.post_id).label('total')
    ).join(tags).group_by(Tag).order_by(desc('total')).limit(5).all()

    return recent, top_tags



class AdminModelView(ModelView):
    def is_accessible(self):
        if 'logged_in' in session:
            return True
        else:
            abort(403)
admin = Admin(app, name='web Admin', template_mode='bootstrap4')
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Post, db.session))
admin.add_view(AdminModelView(Comment, db.session))
admin.add_view(AdminModelView(Like, db.session))
admin.add_view(AdminModelView(Follower, db.session))
admin.add_view(AdminModelView(Message, db.session))



db.create_all()
@app.route('/')
@app.route('/view_home')
def view_home():
    return render_template('home.html')

@app.route('/admin')
@login_required
def admin_page():
    id=current_user.id
    if id==1:
        return render_template('admin.html')
    else:
        flash("Sorry you must be the Admin to access")
        return redirect(url_for('users_account'))
@app.route('/test')
@login_required
def Test_page():
    return render_template('Test.html') 




@app.route('/topluluklar')
def com_page():
    return render_template('Com.html') 



@app.route('/usersss')
def users_pages():
    return render_template('users_page.html') 




@app.route('/login', methods=['GET','POST'])
def Login_page():
    form=forms.LoginForm()
    if form.validate_on_submit():
        attempted_user= User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(form.password.data):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user.username}', category='success')
            return redirect(url_for('Test_page'))
        else:
            flash('Username and password are not match! Please try again', category='danger')  
    return render_template('Login.html', form=form)



@app.route('/google/')
def google():
   
    # Google Oauth Config
    # Get client_id and client_secret from environment variables
    # For developement purpose you can directly put it
    # here inside double quotes
    GOOGLE_CLIENT_ID ="352357782449-f9d8ed83v90gdlf3fa5olc6j9s8251mn.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET ="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"
     
    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
     
    # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

    
 
@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token)
    print(" Google User ", user)
    return redirect(url_for('Test_page'))



@app.route('/register', methods=['GET','POST'])
def register_page():
    form=forms.RegisterForm()
    if form.validate_on_submit():
        user_to_create=User(username=form.username.data, email_address=form.email_address.data, password=form.password1.data,profile_pic=form.profile_pic.data,date_added=form.date_added.data)
        db.session.add(user_to_create)     
        db.session.commit() 
        login_user(user_to_create)
        flash(f"Account created successfully! you are now logged in as {user_to_create.username}", category= 'success')
        return redirect(url_for('Login_page')) 
    if form.errors != {}:#if there are not errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user:{err_msg}')                  
    return render_template('register.html', form=form)    



@app.route('/registeredu')
def edu_page():
    logout_user()
    flash("You have been logged out!", category='info')
    return redirect(url_for('view_home')) 




@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out!", category='info')
    return redirect(url_for('view_home')) 


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
	form = forms.UserForm()
	id = current_user.id
	name_to_update = User.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.email = request.form['email_address']
		name_to_update.username = request.form['username']
		
		

		# Check for profile pic
		if request.files['profile_pic']:
			name_to_update.profile_pic = request.files['profile_pic']

			# Grab Image Name
			pic_filename = secure_filename(name_to_update.profile_pic.filename)
			# Set UUID
			pic_name = str(uuid.uuid1()) + "_" + pic_filename
			# Save That Image
			saver = request.files['profile_pic']
			

			# Change it to a string to save to db
			name_to_update.profile_pic = pic_name
			try:
				db.session.commit()
				saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
				flash("User Updated Successfully!")
				return render_template("update.html", 
					form=form,
					name_to_update = name_to_update)
			except:
				flash("Error!  Looks like there was a problem...try again!")
				return render_template("update.html", 
					form=form,
					name_to_update = name_to_update)
		else:
			db.session.commit()
			flash("User Updated Successfully!")
			return render_template("update.html", 
				form=form, 
				name_to_update = name_to_update)
	else:
		return render_template("update.html", 
				form=form,
				name_to_update = name_to_update,
				id = id)



@app.route('/delete/<int:id>')
@login_required
def delete_page(id):
	# Check logged in id vs. id to delete
	if id == current_user.id:
		user_to_delete = User.query.get_or_404(id)
		username = None
		form = forms.UserForm()

		try:
			db.session.delete(user_to_delete)
			db.session.commit()
			flash("User Deleted Successfully!!")

			our_users = User.query.order_by(User.date_added)
			return render_template("delete_page.html", 
			form=form,
			name=username,
			our_users=our_users)

		except:
			flash("Whoops! There was a problem deleting user, try again...")
			return render_template("delete_page.html", 
			form=form, name=username,our_users=our_users)
	else:
		flash("Sorry, you can't delete that user! ")
		return redirect(url_for('users_account'))


# User Home Page
@app.route('/users',methods=['GET','POST'])
@login_required
def users_account():
    return render_template("user_home.html")
    
@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    form = forms.UserForm()
    email_w_key = current_user.email_address+app.config['SECRET_KEY']
    email_encoding = email_w_key.encode('utf-8')
    hashed_token = hashlib.sha512(email_encoding).hexdigest()
    current_user.access_token = hashed_token
    db.session.commit()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash("User has been found!")
            return redirect(url_for('user', username=form.username.data))
        else:
            flash("User does not exist.")

    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(
        Post.publish_date.desc()).paginate(page=page, per_page=4)
    following = Follower.query.filter_by(follower=current_user).all()
    total_posts = Post.query.all()


    return render_template("dashboard.html", posts=posts, title="My Dashboard", total_posts=len(total_posts), form=form)


#invalid URL    
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404



# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500

#create search fuctions
@app.route('/search', methods=["POST"])
def search():
	form = forms.SearchForm()
	posts = Post.query
	if form.validate_on_submit():
		# Get data from submitted form
		post.searched = form.searched.data
		# Query the Database
		posts = posts.filter(Post.post_content.like('%' + post.searched + '%'))
		posts = posts.order_by(Post.title).all()

		return render_template("search.html",
		 form=form,
		 searched = post.searched,
		 posts = posts)


###################################################################3
# If a user visits another user's profile
@app.route("/user/<username>")
@login_required
def user(username):
    user = User.query.filter_by(username=current_user.username).first()
    page = request.args.get('page', 1, type=int)
    posts = user.posts.paginate(page=page, per_page=3)
    followers = Follower.query.filter_by(followed=user).all()
    followers_total = 0
    for follower in followers:
        followers_total += 1

    return render_template('user.html', title=user.username, user=user, posts=posts, followers_total=followers_total, followers=followers)


# Change Password
@app.route("/changepassword", methods=['GET', 'POST'])
@login_required
def change_password():
    form = forms.ChangePasswordForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email_address=form.email_address.data).first()
        hashed_password = bc.generate_password_hash(
            form.new_password.data).decode('utf-8')
        if form.email_address.data != current_user.email_address:
            flash("Invalid email")
            return redirect(url_for('change_password'))
      
        if not current_user.check_password_correction(form.current_password.data):
            flash("Invalid password")
            return redirect(url_for('change_password'))
        else:
            current_user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated!')
            return redirect(url_for('users_account'))
    return render_template("changepw.html", form=form, title="Change Password")


# Create the post
@app.route("/post", methods=['GET', 'POST'])
@login_required
def create_post():
    form = forms.PostForm()
   
    if form.validate_on_submit():
       
        post = Post(title=form.title.data,
                    post_content=form.post_content.data, author=current_user, image=form.image.data)
        if form.image.data:
            try:
                f = form.image.data
                image_id = str(uuid.uuid4())
                file_name = image_id + '.png'
                file_path = os.path.join(UPLOAD_FOLDER, file_name)
                Image.open(f).save(file_path)
                
            
            except Exception:
                db.session.add(post)
                db.session.commit()
                flash(
                    "C'è stato un problema con l'upload dell'immagine. Cambia immagine e riprova."
                )
                return redirect(url_for("users_account", post=post.id))
        db.session.add(post)
        db.session.commit()
        flash("Your post has been created!")
        return redirect(url_for('users_account'))
    return render_template("create_post.html", form=form, title="New Post", legend="New Post")

@app.route('/posts')
@login_required
def posts():
	# Grab all the posts from the database
	posts = Post.query.filter_by(user_id= current_user.id).order_by(Post.publish_date)
	return render_template("posts.html", posts=posts)


@app.route('/users_posts')
def users_posts():
	# Grab all the posts from the database
	posts = Post.query.order_by(Post.publish_date)
	return render_template("posts.html", posts=posts)

# Post Id
@app.route("/post/<int:post_id>")
@login_required
def post(post_id):
    # Get post
    post = Post.query.get_or_404(post_id)
    tags=post.tags
    return render_template('postid.html', title=post.title, post=post,tags=tags)


# Update Posts
@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    form = forms.PostForm()
  
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if form.validate_on_submit():
        post.title = form.title.data
        post.post_content = form.post_content.data
        db.session.commit()
        return redirect(url_for('users_account'))
    elif request.method == 'GET':
        form.title.data = post.title
        form.post_content.data = post.post_content
    flash("Your post has been updated!", "success")
    return render_template('update_post.html', title='Update Post', form=form, post=post_id)


# Delete the post
@app.route("/post/<int:post_id>/delete", methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    form = forms.PostForm()
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(comments=post).all()
    likes = Like.query.filter_by(liked=post).all()
    if current_user != post.author:
        abort(403)
    for comment in comments:
        db.session.delete(comment)
        db.session.commit()
    for like in likes:
        db.session.delete(like)
        db.session.commit()
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('users_account'))


# Comment on post
@app.route('/post/<int:post_id>/comment', methods=['GET', 'POST'])
@login_required
def comment_on_post(post_id):
    form = forms.CommentForm()
   
    post = Post.query.get_or_404(post_id)
    if form.validate_on_submit():
        comment = Comment(comments=post, commenter=current_user,
                          text=form.comment.data)
        db.session.add(comment)
        db.session.commit()
        flash("Your comment has been posted.", 'success')
        return redirect(url_for('view_comments', post_id=post_id))
    return render_template('comment.html', form=form, title='Comment')


# Delete a comment
@app.route('/post/<int:post_id>/<int:comment_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_comment(post_id, comment_id):

    post = Post.query.get_or_404(post_id)
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash('Your comment has been deleted.', 'success')
    return redirect(url_for('view_comments', post_id=post_id))


# View Comments
@app.route('/post/<int:post_id>/comments', methods=['GET', 'POST'])
@login_required
def view_comments(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template('view_comments.html', comments=comments, post=post, title=f'Comments of {post.title}', total=len(comments))


@app.route('/post/<int:post_id>/<action>', methods=['GET', 'POST'])
@login_required
def like_post(post_id, action):
    post = Post.query.filter_by(id=post_id).first()

    if action == 'like' and current_user.has_liked_post(post):
        flash('Already liked post')
    if action == 'like':
        new_like = Like(liker=current_user, liked=post)
        db.session.add(new_like)
        db.session.commit()

    if action == 'unlike':
        like = Like.query.filter_by(liker=current_user, liked=post).delete()
        db.session.commit()

    return jsonify({"result": "success", "total_likes": post.likes.count(), "liked": current_user.has_liked_post(post)})


@app.route('/post/<int:post_id>/view-likes', methods=['GET', 'POST'])
@login_required
def view_likes(post_id):
 
    post = Post.query.filter_by(id=post_id).first_or_404()
    likes = Like.query.filter_by(liked_id=post_id).all()
    return render_template('likers.html', likes=likes, post=post, title=f'Likes of {post.title}')


@app.route('/<action>/user/<username>', methods=['GET', 'POST'])
@login_required
def follow_action(action, username):
 
    user = User.query.filter_by(username=username).first()

    ''' user variable is a user object. The username paramter in the url
    is used to query from the database to check if the user exists or not.
    In the new_follower variable, the followed=user in the Follower() object
    means that the actual followed person is the user object.
    '''

    if action == 'follow' and current_user.has_followed_user(user):
        return jsonify({"message": "Already following this user."})
    if action == 'follow':
        if User.username == current_user.username:
            return jsonify({"message": "You can't follow yourself."})
        new_follower = Follower(followed=user, follower=current_user)
        db.session.add(new_follower)
        db.session.commit()

    if action == 'unfollow':
        follower = Follower.query.filter_by(
            followed=user, follower=current_user).delete()
        db.session.commit()

    return jsonify({"result": "success", "total_followers": user.followed.count(), "following": current_user.has_followed_user(user)})


@app.route('/user/<username>/view-followers', methods=['GET', 'POST'])
@login_required
def view_followers(username):
  
    user = User.query.filter_by(username=username).first()
    followers = Follower.query.filter_by(followed=user).all()
    return render_template('followers.html', user=user, followers=followers, title=f'Followers of {user.username}')


@app.route('/user/<username>/following', methods=['GET', 'POST'])
@login_required
def view_following(username):
   
    user = User.query.filter_by(username=username).first()
    following = Follower.query.filter_by(follower=user).all()
    return render_template('following.html', user=user, following=following, title=f'{user.username} is following')





@app.route('/api/<token>')
def api(token):
    user = User.query.filter_by(access_token=token).first_or_404()
    posts = Post.query.filter_by(author=user).all()

    followers = Follower.query.filter_by(followed=user).all()
    followed = Follower.query.filter_by(follower=user).all()

    follower_total = 0
    for follower in followers:
        follower_total += 1

    following_total = 0
    for follow in followed:
        following_total += 1

    post_total = 0
    for post in posts:
        post_total += 1

    if user is None:
        return "404"

    return {
        'total_posts': post_total,
        'followers': follower_total,
        'following': following_total,
        'username': f'{user.username}',
        'user_id': f'{user.id}'
    }
    # Reset email


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Forgot your password?',
                  sender='bloggywebsite@gmail.com',
                  recipients=[user.email_address])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password', token=token, _external=True)}
If you did not make this request then simply ignore this email.
'''
    mail.send(msg)


# Forgot password
@app.route("/forgotpassword", methods=["GET", "POST"])
def forgot_password():
    form = forms.ForgotPasswordForm()
    if current_user.is_authenticated:
        return redirect(url_for('users_account'))
    if form.validate_on_submit():
        user = User.query.filter_by(email_address=form.email_address.data).first()
        send_reset_email(user)
        flash("An email has been sent to reset your password.", 'success')

    return render_template("forgotpw.html", form=form, title="Forgot Password")


# Reset password
@app.route("/resetpassword/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('forgot_password'))
    form = forms.ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bc.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('view_home'))
    return render_template('resetpw.html', title='Reset Password', form=form)


    
if __name__ == '__main__':
    app.run(debug=True)


    