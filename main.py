import webapp2
import jinja2
import os
import re
import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import db
import time

"""Mentioning the path of the templates"""

template_dir = os.path.join(os.path.dirname(__file__), 'templates')

"""Loading the templates"""

jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)

"""Unique string to enhance the hashing process"""

secret = 'multibloggolbitlum'


def make_secure_val(val):
    """
    Function returns the encrypted string of the given value
    """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure):
    """
    Function verifies the hashed value and returns the original value
    """
    val = secure.split('|')[0]
    if secure == make_secure_val(val):
        return val


def render_str(template, **params):
    """    
    Function takes a template name and returns a string of rendered template
    """
    t = jinja_env.get_template(template)
    return t.render(params)


class BlogHandler(webapp2.RequestHandler):
    """ Basic Functions to make things easier """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """
        Hash the cookie value and sets the cookie
        """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        """
        Verifies the cookie value
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """Adding secure cookie"""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """
        Clears the cookie which leads to signing out
        """
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """
        Checks if the user is logged in or not
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def make_salt(length=5):
    """Creating salt"""
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """
    Hashing the passord for protection
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """
    Making Sure if the password is not changed
    """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    """Creating a key by the given path"""
    return db.Key.from_path('users', group)


class User(db.Model):
    """
    Creating entity in Google Datastore
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    """
    Helping functions to get data according to the conditions
    """
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):

        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """
    Class used to create Post Entity using Google Datastore
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author_id = db.StringProperty()

    def render(self):
        self.render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p=self)


class Likes(db.Model):
    """
    Class used to create Likes Entity
    """
    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)

    """Get number of likes for an blog id"""

    @classmethod
    def by_author(cls, author_id):
        key = db.GqlQuery('select * from Likes where post = :1',
                          author_id)
        return key.count()

    """Checking the previous likes"""

    @classmethod
    def check_likes(cls, author_id, user_id):
        key = Likes.all().filter('post =', author_id).filter('user =', user_id)
        return key.count()

    def render(self):
        return render_str('post.html', p=self)


class unLikes(db.Model):
    """
    Class to create entity of Unlikes
    """
    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)

    """Get number of unlikes for an blog id"""

    @classmethod
    def by_author(cls, author_id):
        key = db.GqlQuery('select * from unLikes where post = :1',
                          author_id)
        return key.count()

    """Get the number of previous unlikes"""

    @classmethod
    def check_unlikes(cls, author_id, user_id):
        key = unLikes.all().filter('post =', author_id).filter('user =',
                                                               user_id)
        return key.count()

    def render(self):
        return render_str('post.html', p=self)


class Comments(db.Model):
    """
    Class used to create Comments Entity
    """
    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty()

    """
    Getting required data with particular author id
    """
    @classmethod
    def by_author(cls, author_id):
        key = \
            db.GqlQuery('select * from Comments where post = :1 order by created desc',  # NOQA
                        author_id)
        return key

    """
    Getting instance by the unique ID
    """
    @classmethod
    def by_id(cls, uid):
        return Comments.get_by_id(uid, parent=users_key())

    def render(self):
        return render_str('comment.html', c=self)


class FrontPage(BlogHandler):
    """Front Page which lists all blog posts"""

    def get(self):
        """
        Using Gql Query we select posts from table and render into html
        """
        posts = \
            db.GqlQuery('select * from Post order by created desc limit 10'
                        )
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    """
    Blog Post with its own Page we will edit here
    """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        prev_comments = Comments.by_author(post)
        error = ''
        if not post:
            self.render('notfound.html')
            return

        likes = Likes.by_author(post)
        unlikes = unLikes.by_author(post)
        if self.read_secure_cookie('user_id') == "":
            self.redirect('/login')
        self.render(
            'permalink.html',
            post=post,
            likes=likes,
            unlikes=unlikes,
            prev_comments=prev_comments,
            error=error,
            )

    def post(self, post_id):

        """Get all the required data"""

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likes = Likes.by_author(post)
        prev_comments = Comments.by_author(post)
        unlikes = unLikes.by_author(post)
        
        """Checks if the user is logged in"""
        
        if self.user:
            user_id = User.by_name(self.user.name)
            prev_liked = Likes.check_likes(post, user_id)
            prev_unliked = unLikes.check_unlikes(post, user_id)
            """If the user clicks the like button"""

            if self.request.get('like'):

                """
                Checking if the user is liking his own post
                """
                if post.author_id \
                        != str(self.user.key().id()):

                    """
                    Checking the user if liked before
                    """
                    if prev_liked == 0:

                        """Add Like to the database and refresh"""

                        l = Likes(post=post,
                                  user=User.by_name(self.user.name))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/blog/post/%s'
                                      % str(post.key().id()))
                    else:

                        """Otherwise throw the necessary errors"""

                        error = 'You Have already Liked this Post'
                        self.render(
                            'permalink.html',
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            prev_comments=prev_comments,
                            error=error,
                            )
                else:

                    error = 'You cannot like your own post'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            """If the user clicks the unlike button"""

            if self.request.get('unlike'):

                """
                first check if the user is trying to unlike his own post
                """
                if post.author_id \
                   != str(self.user.key().id()):

                    """
                    Then check if the user has unliked this post before
                    """
                    if prev_unliked == 0:

                        """
                        add unlike to the unlikes database and refresh the
                        """

                        ul = unLikes(post=post,
                                     user=User.by_name(self.user.name))
                        ul.put()
                        time.sleep(0.1)
                        self.redirect('/blog/post/%s'
                                      % str(post.key().id()))
                    else:

                        """
                        Otherwise throw the required errors
                        """
                        error = 'You have already Unliked this Post'
                        self.render(
                            'permalink.html',
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            prev_comments=prev_comments,
                            error=error,
                            )
                else:
                    error = 'You cannot unlike your own post'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            """If user clicks the edit button"""

            if self.request.get('edit'):

                """Checks whether the editing user and author is same"""

                if post.author_id \
                   == str(self.user.key().id()):
                    self.redirect('/editpost/%s' % str(post.key().id()))
                else:

                    """If not throw the required errors"""

                    error = 'Cannot edit other people posts'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            """If the user clicks the delete button"""

            if self.request.get('delete'):

                """
                Checks whether the deleting user and author is same
                """
                if post.author_id \
                   == str(self.user.key().id()):
                    self.redirect('/deletepost/%s'
                                  % str(post.key().id()))
                else:

                    """If not throw the required errors"""

                    error = 'Cannot delete other people posts'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            """If the User comments on the post"""

            if self.request.get('comment'):
                comment_content = self.request.get('comment')
                if comment_content:

                    """
                    Adding comment to the Comments database and redericts to
                    the blog post
                    """
                    c = Comments(post=post,
                                 user=User.by_name(self.user.name),
                                 comment=comment_content,
                                 author=str(self.user.key().id()))
                    c.put()
                    time.sleep(0.2)
                    self.redirect('/blog/post/%s'
                                  % str(post.key().id()))
                else:
                    """If not throw the required errors"""
                    error = 'Enter a comment in the area'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            """If the user wants to edit the comment"""

            if self.request.get('edit_comment'):
                c = Comments.by_author(post).get()

                """
                Checking whether the author of comment and user is same
                """
                if str(c.author) == str(self.user.key().id()):
                    self.redirect('/editcomment/%s' % str(c.key().id()))
                else:

                    """If not throw the required errors"""

                    error = "You cannot edit some other user's comment"
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            """If the user wansts to delete the comment"""

            if self.request.get('delete_comment'):
                c = Comments.by_author(post).get()

                """
                Checking whether the author of comment and user is same
                """
                if str(c.author) == str(self.user.key().id()):
                    time.sleep(0.1)
                    self.redirect('/deletecomment/%s'
                                  % str(c.key().id()))
                else:

                    """
                    If not throw the required errors
                    """
                    error = \
                        "You cannot delete some other user's comment"
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )
        else:
            self.redirect('/login')

class NewPost(BlogHandler):
    """Adding new Blog"""
    def get(self):
        self.render('newpost.html')

    """Validations and Rendering of webpage"""

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.user:
            if subject and content:
                p = Post(parent=blog_key(), subject=subject,
                         content=content,
                         author_id=str(self.user.key().id()))
                p.put()
                self.redirect('/blog/post/%s' % str(p.key().id()))
            else:
                error = 'subject and content, please!'
                self.render('newpost.html', subject=subject,
                            content=content, error=error)
        else:
            self.redirect('/login')


class EditPost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = post.subject
        content = post.content
        self.render('edit.html', subject=subject, content=content)

    def post(self, post_id):
        """
        Updates the post
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = Post.get_by_id(int(post_id), parent=blog_key())

        if self.request.get('cancel'):
                return self.redirect('/blog/post/%s' % str(p.key().id()))

        """
        Check both authentication and authorization here (as well as post existence)
        """
        if self.user and p and p.author_id == str(self.user.key().id()):
                subject = self.request.get('subject')
                content = self.request.get('content')
                if subject and content:
                    p.subject = subject
                    p.content = content
                    p.put()
                    self.redirect('/blog/post/%s' % str(p.key().id()))
                else:
                    error = 'subject and content, please!'
                    self.render('edit.html', subject=subject, content=content,
                                error=error)
        else:
            """
            Otherwise send them to the login page
            """
            self.redirect('/login')
        
        

class EditComment(BlogHandler):
    """Edit the comment if any"""
    def get(self, post_id):

        """
        Get's the ID of the author using the post_id
        """
        p = Comments.get_by_id(int(post_id))
        content = p.comment
        self.render('editComment.html', subject=content)

    def post(self, comment_id):
        c = Comments.get_by_id(int(comment_id))
        if self.user and c and c.author == str(self.user.key().id()):
            content = self.request.get('comment_content')
            if content:
                c.comment = content
                c.put()
                self.redirect('/blog/')
            else:
                error = 'Add Comment, please!'
                self.render('editComment.html', error=error)
        else:
            self.redirect('/login')
        """
        Changes the data from the database if any else throws an error
        """
        

class DeletePost(BlogHandler):
    """Deletes Post Data from the Comments Table"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = Post.get_by_id(int(post_id), parent=blog_key())

        if self.user and p and post.author_id == str(self.user.key().id()):
                p.delete()
                self.redirect('/blog')
        else:
            self.redirect('/login')
        

class DeleteComment(BlogHandler):
    """
    Delete Comment data from the Comments Table
    """
    def get(self, post_id):
        c = Comments.get_by_id(int(comment_id))
        if self.user and c and c.author == str(self.user.key().id()):
            c.delete()
            self.redirect('/blog')
        else:
            self.redirect('/login')
        

"""
Regular expressions used to validate the username
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


"""
Regular expressions used to validate the password
"""
PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


"""
Regular expressions used to validate the email(optional)
"""
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    """
    Registration of new User with proper validations
    """
    def get(self):
        self.render('signup-form.html')

    def post(self):
        error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = 'This is not a valid username'
            error = True

        if not valid_password(self.password):
            params['error_password'] = 'This is not a valid password'
            error = True
        elif self.password != self.verify:
            params['error_verify'] = "Password didn't match"
            error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            error = True

        if error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    """Raising Exception if got any other error"""

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """
    Redirects to welcome page and make sure user doesn't exist
    Inherits the Signup Class
    """
    def done(self):

        """Making Sure that user deosn't exist"""

        u = User.by_name(self.username)
        if u:
            msg = 'User already exists'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Welcome(BlogHandler):
    """
    Welcomes the user with his/her username
    """
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Login(BlogHandler):
    """
    Verifies the login data with registered users and redericts to homepage
    """
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    """
    Clears the cookie and User gets logout
    """
    def get(self):
        self.logout()
        self.redirect('/blog')


class MainHandler(BlogHandler):
    """
    Redirects to the HomePage of the website
    """
    def get(self):
        self.redirect('/blog')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog/?', FrontPage),
    ('/blog/post/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/editpost/([0-9]+)', EditPost),
    ('/deletepost/([0-9]+)', DeletePost),
    ('/editcomment/([0-9]+)', EditComment),
    ('/deletecomment/([0-9]+)', DeleteComment),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ], debug=True) 
