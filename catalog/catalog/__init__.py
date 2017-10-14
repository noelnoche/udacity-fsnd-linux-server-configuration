"""
The Flask class and Flask's Blueprint registration is placed
in the catalog module's global scope.

"""

import os
from flask import Flask
from login.controller import bp_login
from main.controller import bp_main
from rlimiter.controller import bp_rlimit

app = Flask(__name__)

# For file upload feature
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # Restrict file size to 1MB
app.secret_key = os.environ["SECRET"]
app.register_blueprint(bp_login, url_prefix="/user")
app.register_blueprint(bp_main, url_prefix="/catalog")
app.register_blueprint(bp_rlimit, url_prefix="/rlimit")
