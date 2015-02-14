import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import db
import jinja2
import os

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))

##### User utilities
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

### User model

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

### Page structure

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def page_key(name = 'default'):
    return db.Key.from_path('pages', name)

class Page(db.Model):
    version = db.IntegerProperty(required = True)
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def make_page(cls, version, title, content):
        return Page(parent =  page_key(),
                    version = version,
                    title = title,
                    content = content)

    @classmethod
    def by_title(cls, title):
        p = Page.all().filter('title =', title).get()
        return p

    @classmethod
    def get_version(cls, title, version):
        p = Page.all().filter('title =', title).filter('version =', version).get()
        return p

    @classmethod
    def latest_version(cls, title):
        p = Page.all().filter('title =', title).order('-version').get()
        return p

    @classmethod
    def version_history(cls, title):
        version_history = Page.all().filter('title =', title).order('version')
        return version_history

    def edit_link(self):
        return "/edit%s" % title

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("temp.html", p = self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'version': self.version,
             'title': self.title,
             'edit_link': "/_edit%s" % self.title,
             'content': str(self.content),
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d


### page history
def history_key(group = 'default'):
    return db.Key.from_path('history', group)

class History(db.Model):
    title = db.StringProperty(required = True)
    added = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def add_page(cls, title):
        return History(parent = history_key(),
                        title = title)

    @classmethod
    def most_recent(cls):
        last_page = History.all().order('-added').get()
        return last_page.title

    @classmethod
    def dump(cls):
        history = History.all().order('-added')
        return history
