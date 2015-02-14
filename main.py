import os
import re
import random
import hashlib
import hmac
import logging
import json
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

import datastore as d
import utilities as utils

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))


secret = open("authentication.txt", 'r').read()
locked_pages = ["/login", "/logout", "/signup", "/_page_history", "/_history"]
PAGE_RE = r'(/?(?:[a-zA-Z0-9_-]+/?)*)'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):  

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def get_params(self, title = None, edit = None, version = None, history = None):
        uid = self.read_secure_cookie('user_id')
        tools = {}

        if uid:
            user = d.User.by_id(int(uid))
            if edit:
                if version:
                    tools["a"] = ["view", "%s?view=%s" % (title,version)]
                else:
                    tools["a"] = ["view", "/%s" % title]
                tools["b"] = ["history", "/_history%s" % title]
            elif history:
                tools["a"] = ["view", "/%s" % title]
                tools["b"] = ["history", ""]
            else:
                if version:
                    tools["a"] = ["edit", "/_edit%s?edit=%s" % (title,version)]
                else:
                    tools["a"] = ["edit", "/_edit%s" % title]
                tools["b"] = ["history", "/_history%s" % title]
            tools["c"] = ["(%s)" % user.name, ""]
            tools["d"] = ["log out", "/logout"]

        else:
            tools["a"] = ["", ""]
            tools["b"] = ["", ""]
            tools["c"] = ["log in", "/login"]
            tools["d"] = ["register", "/signup"]
        return tools

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and d.User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class Signup(Handler):
    def get(self):
        params = self.get_params()
        self.render("signup.html", **params)

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = self.get_params()
        params["username"] = self.username
        params["email"] = self.email

        if not utils.valid_username(self.username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        if not utils.valid_password(self.password):
            params['password_error'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Your passwords didn't match."
            have_error = True

        if self.email and not utils.valid_email(self.email):
            params['email_error'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        #make sure the user doesn't already exist
        u = d.User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = d.User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            last_page = d.History.most_recent()
            self.redirect("%s" % last_page) 
            #self.write("Welcome mate!") # add logic - header changes, return to current page

class Login(Handler):
    def get(self):
        params = self.get_params()
        self.render("login.html", **params)

    def post(self):
        params = self.get_params()
        username = self.request.get('username')
        password = self.request.get('password')

        u = d.User.login(username, password)
        if u:
            self.login(u)
            last_page = d.History.most_recent()
            self.redirect("%s" % last_page)
            #self.write("%s" % title) # update with logic! - header changes, return to current page
        else:
            params["error"] = 'Invalid login'
            self.render('login.html', **params)

class Logout(Handler):
    def get(self):
        params = self.get_params()
        self.logout()
        last_page = d.History.most_recent()
        self.redirect("%s" % last_page)
        #self.render("logout.html", **params) # add logic - header changes, remain on existing page

class EditPage(Handler):
    def get(self, title):
        #params = dict(edit = "", page = "")
        #get current page content to populate 
        # new_title = title[6:]
        # self.write("title: %s, new_title: %s" % (title, new_title))

        ### check authentication + that page isn't in locked_pages
        uid = self.read_secure_cookie('user_id')

        if (title in locked_pages):
            self.redirect("/%s" % title)
        if not uid:
            self.redirect("/login")

        title = "/" + title
        #self.write("%s" % title)
        edit_version = self.request.get('edit')
        if edit_version:
            #get version
            params = self.get_params(title = title, edit = True, version = edit_version)
            p = d.Page.get_version(title, int(edit_version))
            params["title"] = title
            params["content"] = p.content
            self.render("edit.html", **params)
        else:
            params = self.get_params(title = title, edit = True)
            params["title"] = title
            p = d.Page.latest_version(title) #get latest version
            if p:
                params["content"] = p.content #if page exists, populate latest content
            else:
                params["content"] = "" 
            self.render("edit.html", **params)

    def post(self, title):
        #create page/u
        new_title = "/" + title
        content = self.request.get('content')
        p = d.Page.latest_version(new_title)
        if p:
            new_version = p.version + 1
            newpage = d.Page.make_page(new_version, new_title, content)
            newpage.put()
            #self.write("/%s" % title)
            time.sleep(0.5)
            self.redirect("/%s" % title)
        else:
            newpage = d.Page.make_page(1, new_title, content)
            newpage.put()
            #self.write("/%s" % title)
            time.sleep(0.5)
            self.redirect("/%s" % title)

        #self.render("edit.html", edit = "", page = "")

class WikiPage(Handler):
    def get(self, title):
        view_version = self.request.get('view')
        edit_version = self.request.get('edit')

        
        d.History.add_page(title).put() #add current page to history

        if edit_version:
            self.redirect("/edit%s/?edit=%s" % (title, edit_version))

        if view_version:
            params = self.get_params(title = title, version = view_version)
            p = d.Page.get_version(title, int(view_version))
            params["p"] = p
            self.render("page.html", **params)
        else:
            #check for latest version, if page doesn't exist, redirect to edit page
            params = self.get_params(title = title)
            p = d.Page.latest_version(title)
            if p:
                #self.write("%s" % p.content)
                params["p"] = p
                self.render("page.html", **params)
            else:
                #self.write("title = %s" % title)
                self.redirect("/_edit%s" % title)
                #self.render("page.html", p) #redirect to edit

class PageHistory(Handler):
    def get(self):
        params = self.get_params()
        #last_page = d.History.most_recent()
        q = d.History.dump()
        history = []
        #self.write("%s" % last_page)
        #params["history"] = history
        for page in q: # for each entry in page history, append to list
            history.insert(0,page.title)
            #self.write("%s <br>" % page.title)
        params["history"] = history
        self.render("history.html", **params) # render page history

class History(Handler):
    def get(self, title):
        params = self.get_params(title = title, history = True)
        q = d.Page.version_history("/" + title)
        history = []
        for v in q: # for each page, append data to list
            history.insert(0, v.as_dict())
        params["h"] = history
        self.render("page_history.html", **params)

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_history/' + PAGE_RE, History),
                               ('/_pagehistory', PageHistory),
                               ('/_edit/' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)


