#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import hmac

import re

import random
import string
import hashlib
import logging

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw, salt = None):
    if(not salt):
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    salt = h.split(",")[1]
    new_hash = make_pw_hash(name, pw, salt)
    print new_hash
    return new_hash == h

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")




SECRET = "IAMTOPSECRET"

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment( loader=jinja2.FileSystemLoader(template_dir),
								autoescape=True)

from google.appengine.ext import db

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))
def check_secure_val(h):
    ###Your code here
    val = h.split("|")
    if len(val) == 2 and hash_str(val[0]) == val[1]:
        return val[0]

class Post(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
	user_id = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

def validate_user(text):
	return USER_RE.match(text)

def check_user_exists(text):
	user_exist = db.GqlQuery("SELECT * FROM User WHERE user_id = :user", user = text).get()
	return user_exist 

def check_user(userName, password):
	db_user = check_user_exists(userName)
	return valid_pw(userName, password, db_user.password), db_user

def validate_password(passwod):
	return PASSWORD_RE.match(passwod)
def validate_email(email):
	return EMAIL_RE.match(email)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kwargs):
		self.response.write(*a, **kwargs)
	def render_string(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self, template, **params):
		self.write(self.render_string(template, **params))
	def get_from_request(self, param):
		return self.request.get(param)
class MainHandler(Handler):
	def get(self):
		userId = None
		user_cookie_val = self.request.cookies.get("user")
		if(user_cookie_val):
			userId = check_secure_val(user_cookie_val)
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
		self.render("homeTemplate.html", posts = posts, userName = userId)

class AdminHandler(Handler):
	def get(self):
		self.render("adminPage.html")
	def post(self):
		errors = {}
		errors["errors_present"] = False
		blog_title = self.request.get("blogTitle")
		blog_content = self.request.get("blogContent")
		if not blog_title:
			errors["title_error"] = "Please enter a valid Title!"
			errors["errors_present"] = True
		if not blog_content:
			errors["content_error"] = "Please enter a Valid Content!"
			errors["errors_present"] = True

		if(errors["errors_present"]):
			self.render("adminPage.html", title = blog_title, content = blog_content, errors = errors)
		else:
			post = Post(title = blog_title, content = blog_content)
			post.put()
			self.redirect("/blog/" + str(post.key().id()))

class BlogEntryHandler(Handler):
	def get(self, post_id = ""):
		try:
			post = Post.get_by_id(int(post_id))
			if post:
				self.render("postTemplate.html", post = post)
			else:
				raise ValueError('Post Not Found');
		except Exception as e:
			print str(e)
			self.redirect("/")

class CookieCheck(Handler):
	def get(self):
		self.response.headers["Content-Type"] = "text/plain"
		visits = 0
		visit_cookie_val = self.request.cookies.get("visits")
		if visit_cookie_val:
			cookie_val = check_secure_val(visit_cookie_val)
			if cookie_val:
				visits = int(cookie_val)
		visits = visits + 1
		new_cookie_val = make_secure_val(str(visits))
		self.response.headers.add_header("Set-Cookie", "visits=%s" % new_cookie_val)
		self.write("You have visited this page %s Times" % visits)

class SignupHandler(Handler):
	def get(self):
		page = {
			"errors": {

			}
		}
		self.render("signupTemplate.html", page = page)
	def post(self):
		page = {
			"title": "Please Check the Errors In the Form",
			"errors": {},
			"hasErrors": False
		}
		userName = self.get_from_request("userName")
		password = self.get_from_request("password")
		rePass = self.get_from_request("rePassword")
		email = self.get_from_request("email")

		if not (userName and validate_user(userName) ):
			page["errors"]["userName"] = True
			page["hasErrors"] = True
		else:
			if check_user_exists(userName):
				page["errors"]["userExists"] = True
				page["hasErrors"] = True

		if not (password and validate_password(password)):
			page["errors"]["password"] = True
			page["hasErrors"] = True
		else:
			if not (rePass and rePass == password):
				page["errors"]["rePass"] = True
				page["hasErrors"] = True

		if email and not validate_email(email):
			page["errors"]["email"] = True
			page["hasErrors"] = True
 	
 		if page["hasErrors"]:
			self.render("signupTemplate.html", page = page)
		else:
			user = User(user_id = userName, password = make_pw_hash(userName, password), email = email)
			user.put()
			secure_user_id = make_secure_val(userName)
			self.response.headers["Content-Type"] = "text/plain"
			self.response.headers.add_header("Set-Cookie", "user=%s" % str(secure_user_id))
			self.redirect("/")
class LoginHandler(Handler):
	def get(self):
		page = {
			"errors": {

			}
		}
		self.render("loginTemplate.html", page = page)
	def post(self):
		page = {
			"title": "Please Check the Errors In the Form",
			"errors": {},
			"hasErrors": False
		}
		page["userName"] = userName = self.get_from_request("userName")
		password = self.get_from_request("password")
		if not (userName and validate_user(userName) ):
			page["hasErrors"] = True
		if not (password and validate_password(password)):
			page["hasErrors"] = True

		user_identity_confirmed, valid_user = check_user(userName, password)
		if(not user_identity_confirmed):
			page["hasErrors"] = True

		if page["hasErrors"]:
			self.render("loginTemplate.html", page = page)
		else:
			secure_user_id = make_secure_val(valid_user.user_id)
			self.response.headers["Content-Type"] = "text/plain"
			self.response.headers.add_header("Set-Cookie", "user=%s" % str(secure_user_id))
			self.redirect("/")
app = webapp2.WSGIApplication([
    ('/', MainHandler), 
    ("/add_post", AdminHandler), 
    ("/blog/(.*)", BlogEntryHandler),
    ("/cookie", CookieCheck),
    ("/signup", SignupHandler),
    ("/login", LoginHandler)
], debug=True)
