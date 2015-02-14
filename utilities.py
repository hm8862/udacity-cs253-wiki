###Blog utility functions

import os, sys
import webapp2
import jinja2
import re
import hmac
import json, urllib2
import time
from google.appengine.ext import db

fi = open("authentication.txt", 'r')
SECRET = fi.read()

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(s):
    return USER_RE.match(s)

def valid_password(s):
    return PASSWORD_RE.match(s)

def valid_email(s):
    return EMAIL_RE.match(s)

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def get_user(cookie):
    user_id = cookie[:cookie.find("|")]
    key = db.Key.from_path("User", int(user_id), parent=blog_key())
    user = db.get(key)
    return user

def check_user(cookie):
    #check user exists and that cookie is valid
    user = get_user(cookie)
    if check_secure_val(cookie) and user:
        return user
    return None

def build_json(posts, leng):
    #build json output from posts
    if not posts:
        return
    j = []
    
    if leng == 1:
        j = {"content": "%s" % posts.content, "created": posts.created.strftime("%a %b %H:%M:%S %Y"), 
            "last_modified": posts.last_modified.strftime("%a %b %H:%M:%S %Y"), "subject": "%s" % posts.subject}
    else:
        for post in posts:
            j.append({"content": "%s" % post.content, "created": post.created.strftime("%a %b %H:%M:%S %Y"), 
            "last_modified": post.last_modified.strftime("%a %b %H:%M:%S %Y"), "subject": "%s" % post.subject})
    return json.dumps(j)

