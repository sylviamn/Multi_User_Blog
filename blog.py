import os
import re
import random
import hashlib
import hmac
import time
import webapp2
import jinja2
from string import letters
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'slwfekj243skjfshv234'


################## Global functions ##################

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


################## Blog Handler ###################
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


################# User Entity ####################
class User(db.Model):
    #user attributes
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #get user by id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    #get user by name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    #create new user
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    #login user if valid
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


#################### Like Entity ##################
class Like(db.Model):
    #like attributes
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)


#################### Comment Entity ##################
class Comment(db.Model):
    #comment attributes
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment_text = db.TextProperty(required = True)

    #render comments
    def render(self, user_id):
        self._render_text = self.comment_text.replace('\n', '<br>')
        createdby = User.by_id(self.user_id)
        user = User.by_id(user_id)

        return render_str("comment.html", c = self, createdby = createdby.name, username = user.name)


#################### Post Entity ##################
class Post(db.Model):
    #post attributes
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty(required=True)

    #render posts
    def render(self, user_id):
        self._render_text = self.content.replace('\n', '<br>')
        createdby = User.by_id(self.user_id)
        user = User.by_id(user_id)

        l = Like.all().filter('post_id =', self.key().id())
        likecount = l.count()
        
        likeuser = Like.all().filter('post_id =', self.key().id()).filter('user_id =', int(user_id)).get()

        c = Comment.all().filter('post_id =', self.key().id())
        commentcount = c.count()

        return render_str("post.html", p = self, createdby = createdby.name, username = user.name, likecount = likecount, likeuser = likeuser, commentcount = commentcount)


####################### Handlers ####################
### Home page ###
class Welcome(BlogHandler):
    def get(self):
        #if user not signed in show login page else show welcome page
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/login')


### Signup page ###
class Signup(BlogHandler):
    def get(self):
        #load sign up page with form
        self.render("signupform.html")

    def post(self):
        #create new user account if no errors
        have_error = False

        #get user attributes from sign up form
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        #check to make sure values from form are valid
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        #if error exists reload sign up form
        if have_error:
            self.render('signupform.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


### Create user entity and login ###
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)

        if u:
            msg = 'That user already exists.'
            self.render('signupform.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


### Login page ###
class Login(BlogHandler):
    def get(self):
        #load login page with form
        self.render('loginform.html')

    def post(self):
        #get login info from form
        username = self.request.get('username')
        password = self.request.get('password')

        #get user based on login info
        u = User.login(username, password)

        # if user does not exist show error else login user
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('loginform.html', error = msg)


### Logout user ###
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


### Main blog page ###
class MainPage(BlogHandler):
    def get(self):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get top 10 posts and show in order of created date
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('blog.html', posts = posts)


### Single post page ###
class BlogPage(BlogHandler):
    def get(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post entity info
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        #get post comments
        comments = Comment.all().filter('post_id =', int(post_id)).order('-created')

        #if post does not exist show error
        if not post:
            self.error(404)
            return

        #load single post page
        self.render("permalink.html", post = post, comments = comments)


### New post page with form ###
class NewPost(BlogHandler):
    def get(self):
        #if user not logged in redirect to login page
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/")

    def post(self):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post info from form
        subject = self.request.get('subject')
        content = self.request.get('content')
        post_user = self.user.key().id()

        #check for valid form entries, create post entity
        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user_id=post_user)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


### Edit post page with form ###
class EditPost(BlogHandler):
    def get(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post entity info
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = post.subject
        content = post.content

        #if post does not exist show error
        if not post:
            self.error(404)
            return

        #user can only edit posts they created
        if self.user.key().id() == post.user_id:
            self.render("editpost.html", subject=subject, content=content)
        else:
            error = "You do not have access to edit this post."
            self.render("error.html", error = error)

    def post(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get updated post attributes from form
        subject = self.request.get('subject')
        content = self.request.get('content')

        #check for valid entries
        if subject and content:
            #set existing post attributes to new attributes
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content

            #update post with edits
            post.put()

            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject, content=content, error=error)


### Delete post page ###
class DeletePost(BlogHandler):
    def get(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post entity info
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        #if post does not exist show error
        if not post:
            self.error(404)
            return

        #user can only delete posts they created
        if self.user.key().id() == post.user_id:
            self.render("deletepost.html")
        else:
            error = "You do not have access to delete this post."
            self.render("error.html", error = error)

    def post(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post entity info and delete
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        post.delete()

        #time delay before redirect to show changes on page
        time.sleep(0.1)
        self.redirect('/blog')


### Like post ###
class LikePost(BlogHandler):
    def get(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post entity info
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        #if post does not exist show error
        if not post:
            self.error(404)
            return

        user_id = self.user.key().id()

        #check if user has liked post
        l = Like.all().filter('post_id =', int(post_id)).filter('user_id =', user_id).get()

        #if user has liked post already show error
        if l is not None:
            error = "You cannot like a post more than once"
            self.render("error.html", error = error)
            return

        #user can only like posts that they did not create
        if user_id != post.user_id:
            l = Like(user_id = user_id, post_id = int(post_id))
            l.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % post_id)
        else:
            error = "You cannot like your own post."
            self.render("error.html", error = error)


### Unlike post ###
class UnlikePost(BlogHandler):
    def get(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post entity info
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        #if post does not exist show error
        if not post:
            self.error(404)
            return

        user_id = self.user.key().id()

        #check if user has liked post
        l = Like.all().filter('post_id =', int(post_id)).filter('user_id =', user_id).get()

        #if user has not liked post they cannot unlike post
        if l is None:
            error = "You cannot unlike an item you have not liked yet."
            self.render("error.html", error = error)
            return

        #if user liked post, delete like entity to unlike
        l_key = l.key()
        userlike = db.get(l_key)
        userlike.delete()
        time.sleep(0.1)
        self.redirect('/blog/%s' % post_id)


### New post comment form ###
class NewComment(BlogHandler):
    def get(self, post_id):
        #if user not logged in redirect to login page
        if self.user:
            self.render("newcomment.html")
        else:
            self.redirect("/")

    def post(self, post_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get post entity info
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        #if post does not exist show error
        if not post:
            self.error(404)
            return

        #get post comment info from form
        comment_text = self.request.get('comment_text')
        comment_user = self.user.key().id()

        #check for valid entries, create comment entity
        if comment_text:
            c = Comment(user_id = comment_user, post_id = int(post_id), comment_text=comment_text)
            c.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % post_id)
        else:
            error = "comment cannot be blank!"
            self.render("newcomment.html", comment_text=comment_text, error=error)


### Edit post comment form ###
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get comment entity info
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        comment_text = comment.comment_text

        #if comment does not exist show error
        if not comment:
            self.error(404)
            return

        #user can only edit comments that they have created
        if self.user.key().id() == comment.user_id:
            self.render("editcomment.html", comment_text = comment_text)
        else:
            error = "You do not have access to edit this comment."
            self.render("error.html", error = error)

    def post(self, post_id, comment_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get updated comment info from form
        comment_text = self.request.get('comment_text')

        #check for valid entries, update comment entity
        if comment_text:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            comment.comment_text = comment_text

            comment.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % post_id)
        else:
            error = "comment cannot be blank!"
            self.render("editcomment.html", comment_text = comment_text, error=error)


### Delete comment page ###
class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get comment entity info
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        #if comment does not exist show error
        if not comment:
            self.error(404)
            return

        #user can only delete comments they created
        if self.user.key().id() == comment.user_id:
            self.render("deletecomment.html")
        else:
            error = "You do not have access to delete this comment."
            self.render("error.html", error = error)

    def post(self, post_id, comment_id):
        #if user not logged in redirect to login page
        if not self.user:
            self.redirect('/')

        #get comment entity info and delete
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        comment.delete()

        time.sleep(0.1)
        self.redirect('/blog/%s' % post_id)


app = webapp2.WSGIApplication([('/', Welcome),
							   ('/blog/?', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)/editpost', EditPost),
                               ('/blog/([0-9]+)/deletepost', DeletePost),
                               ('/blog/([0-9]+)/likepost', LikePost),
                               ('/blog/([0-9]+)/unlikepost', UnlikePost),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/blog/([0-9]+)/([0-9]+)/editcomment', EditComment),
                               ('/blog/([0-9]+)/([0-9]+)/deletecomment', DeleteComment),
                               ('/blog/([0-9]+)', BlogPage),
                               ('/signup', Register),                                                            						   
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
