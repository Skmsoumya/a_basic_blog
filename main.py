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

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment( loader=jinja2.FileSystemLoader(template_dir),
								autoescape=True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kwargs):
		self.response.write(*a, **kwargs)
	def render_string(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self, template, **params):
		self.write(self.render_string(template, **params))

class MainHandler(Handler):
	def get(self):
		self.render("homeTemplate.html")

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
			self.render("post saved sucessfully")

app = webapp2.WSGIApplication([
    ('/', MainHandler), ("/add_post", AdminHandler)
], debug=True)
