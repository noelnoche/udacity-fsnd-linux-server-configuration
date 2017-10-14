"""
This module contains functions for user login and various signup methods.

"""

import json
import random
import string
import re
import os
import requests
from flask import (abort, Blueprint, flash, g, jsonify, make_response,
                   redirect, render_template, request, url_for)
from flask import session as login_session
from catalog.db_setup import User, Category
from catalog.connection_manager import DBSession
from sqlalchemy.orm.exc import NoResultFound

# Google Plus specific
# from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import FlowExchangeError
from oauth2client.client import OAuth2Credentials

# Twitter specific
# https://github.com/joestump/python-oauth2
import oauth2 as oauth
import base64
import time
import urllib
import urlparse

# Google Plus authorization data
GPL_APP_ID = os.environ["GPL_APP_ID"]
GPL_CLT_ID = os.environ["GPL_CLT_ID"]
GPL_SEC = os.environ["GPL_SEC"]
GPL_RED_URI = ([
    "http://localhost:8000/catalog",
    "http://localhost:8000/user/connect_gpl",
    "http://ec2-35-163-157-140.us-west-2.compute.amazonaws.com/catalog",
    "http://ec2-35-163-157-140.us-west-2.compute.amazonaws.com/user/"
    "connect_gpl"])

# Facebook authorization data
FB_APP_ID = os.environ["FB_APP_ID"]
FB_SEC = os.environ["FB_SEC"]

# Twitter authorization data
TWT_OWN_ID = os.environ["TWT_OWN_ID"]
TWT_CON_KEY = os.environ["TWT_CON_KEY"]
TWT_CLT_SEC = os.environ["TWT_CLT_SEC"]
TWT_AXS_TKN = os.environ["TWT_AXS_TKN"]
TWT_TKN_SEC = os.environ["TWT_TKN_SEC"]

# For standard login validation
USER_RE = re.compile(r"^[a-zA-Z0-9_]{7,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PASS_RE = re.compile(r"^.{12,24}$")

# Login now accessed in other modules via @bp_login.route(URL)
bp_login = Blueprint("bp_login", __name__, template_folder="templates")

session = DBSession()


def create_user(logses):
    """Creates a new user from values stored in login_session.

    Args:
        logses (:obj:`dict` of :obj:`str`): SQLAlchemy Session object,
            imported as `login_session`.
    """

    email = logses["email"]
    new_user = User(username=logses["username"], email=email,
                    picture=logses["picture"])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=email).one()

    # All new users get a permanent default folder called "Unsorted"
    new_category = Category(name="Unsorted", user_id=user.id)
    session.add(new_category)
    session.commit()

    # They also get their own directory for storing image files
    upload_dir = "/var/www/catalog/catalog/static/uploads"
    user_dir = os.path.join(upload_dir, str(user.id))
    os.mkdir(user_dir)

    print "CREATED NEW USER!"
    return user


def get_user_info(usrid):
    """Uses user ID to get a user's database record.

    Args:
        userid (int): User's accociated database `id` key value.
    """

    try:
        user = session.query(User).filter_by(id=usrid).one()
        return user
    except NoResultFound:
        msg = "Could not find that user's data."
        return None


def get_user_id(email):
    """Gets user id from the database based on email.

    Args:
        email (str): User's associated email address.
    """

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        msg = "Could not find that user's data."
        return None


def gen_csrf_token():
    """Generates a random string to guard against CSRF attacks."""

    return "".join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))


def purge_session():
    """Clears out all login_session values."""

    access_token = login_session["access_token"]
    provider = login_session["provider"]

    if provider == "google":
        revoke_url = ("https://accounts.google.com/o/oauth2/revoke?token={}"
                      .format(access_token))
        revoke_data = requests.get(revoke_url)
        revoke_obj = json.loads(revoke_data.text)

        if "error" not in revoke_obj.keys():
            del login_session["gplus_id"]
        else:
            msg = ("Error @purge_session -- {}"
                   .format(revoke_obj["error_description"]))
            response = make_response(jsonify(response=msg), 401)
            return response

    if provider == "facebook":
        facebook_id = login_session["facebook_id"]
        revoke_url = ("https://graph.facebook.com/{}/permissions?"
                      "access_token={}".format(facebook_id, access_token))
        revoke_data = requests.get(revoke_url)
        revoke_obj = json.loads(revoke_data.text)

        if "error" not in revoke_obj.keys():
            del login_session["facebook_id"]
        else:
            msg = ("Error @purge_session -- {}"
                   .format(revoke_obj["error"]["message"]))
            response = make_response(jsonify(response=msg), 401)
            return response

    if provider == "twitter":
        del login_session["twt_token_secret"]

    del login_session["access_token"]
    del login_session["user_id"]
    del login_session["username"]
    del login_session["email"]
    del login_session["picture"]
    del login_session["state"]
    del login_session["provider"]

    return True


def valid_username(username):
    """Checks if username meets conditions.

    Args:
        username (str): User-supplied username value.
    """

    return username and USER_RE.match(username)


def valid_email(email):
    """Checks if email is valid.

    Args:
        email (str): User-supplied email value.
    """

    return EMAIL_RE.match(email)


def valid_password(password):
    """Checks if password is between 12-24 characters in length.

    Args:
        password (str): User-supplied password.
    """

    return password and PASS_RE.match(password)


@bp_login.route("/signup_redirect", methods=["POST"])
def signup_redirect():
    """Handler for redirecting new user to sign up screen."""

    if request.args.get("state") != login_session["state"]:
        abort(401)
    else:
        redirect_url = url_for("bp_login.signup")
        response = make_response(jsonify(redirect_url=redirect_url), 200)
        return response


@bp_login.route("/signup", methods=["GET", "POST"])
def signup():
    """Handler for direct signup."""

    if request.method == "POST":
        fm_state = request.form["csrf-token"]
        if fm_state != login_session["state"]:
            abort(401)

        has_error = False
        errors = {}
        fm_username = request.form["fm_username"]
        fm_email = request.form["fm_email"]
        fm_email_cnf = request.form["fm_email_cnf"]
        fm_passd = request.form["fm_passd"]
        fm_passd_cnf = request.form["fm_passd_cnf"]
        db_records = session.query(User).filter_by(email=fm_email).count()

        if (fm_username == "" or fm_email == "" or fm_email_cnf == "" or
                fm_passd == "" or fm_passd_cnf == ""):
            has_error = True
            errors["err_fields"] = "Please fill in all fields."
        if not valid_username(fm_username):
            has_error = True
            msg = ("Username must be between 7 and 20 alphanumeric "
                   "characters. Underscores are permitted.")
            errors["err_username"] = msg
        if not valid_email(fm_email):
            has_error = True
            errors["err_email"] = "Your email is not valid."
        if not valid_password(fm_passd):
            has_error = True
            msg = "Your password should be between 12 and 24 characters long."
            errors["pass_len"] = msg
        if (fm_email != fm_email_cnf) or (fm_passd != fm_passd_cnf):
            has_error = True
            errors["err_cnf"] = "Mismatched email or password."
        if db_records == 1:
            flash("That user already exists!")
            return redirect(url_for("bp_login.signup"), code=302)
        if db_records > 1:
            msg = ("We found multiple accounts with that email address. "
                   "Please report this issue to the system administrator.")
            response = make_response(jsonify(response=msg), 404)
            return response

        if has_error is True:
            state = login_session["state"]
            return render_template("signup.html", STATE=state,
                                   USERNAME=fm_username, EMAIL=fm_email,
                                   EMAIL_CNF=fm_email_cnf, PASSD=fm_passd,
                                   PASSD_CNF=fm_passd_cnf, ERRORS=errors)
        else:
            user = User(username=fm_username, email=fm_email)
            user.hash_password(fm_passd)
            session.add(user)
            session.commit()

            # Create default permanent "Unsorted" folder and image directory
            new_category = Category(name="Unsorted", user_id=user.id)
            session.add(new_category)
            session.commit()
            upload_dir = "/var/www/catalog/catalog/static/uploads"
            user_dir = os.path.join(upload_dir, str(user.id))
            os.mkdir(user_dir)

            # Some values set to None so that `purge_session()` works correctly
            login_session["provider"] = "catalog"
            login_session["user_id"] = user.id
            login_session["username"] = user.username
            login_session["email"] = user.email
            login_session["picture"] = None
            login_session["access_token"] = None

            print "CREATED NEW USER!"
            flash("Registration successful!")
            return redirect(url_for("bp_main.welcome"), code=302)
    else:
        state = login_session["state"] = gen_csrf_token()
        return render_template("signup.html", STATE=state, USERNAME="",
                               EMAIL="", EMAIL_CNF="", PASSD="", PASSD_CNF="",
                               ERRORS={})


@bp_login.route("/settings", methods=["GET", "POST"])
def user_settings():
    """Handler for the user settings page."""

    if "username" not in login_session:
        abort(401)

    user_id = login_session["user_id"]
    provider = login_session["provider"]

    if provider == "google":
        msg = "Logged in with Google Plus"
    if provider == "facebook":
        msg = "Logged in with Facebook"
    if provider == "twitter":
        msg = "Logged in with Twitter"

    try:
        user = session.query(User).filter_by(id=user_id).one()
    except NoResultFound:
        msg = "<strong>Could not find that user's data.</strong>"
        response = make_response(msg, 404)
        return response

    if provider != "catalog":
        if request.method == "POST":
            has_error = False
            errors = {}
            fm_state = request.form["csrf-token"]
            fm_email = request.form["fm-email"]
            fm_email_cnf = request.form["fm-email-cnf"]
            fm_yn = request.form["fm-yn"]

            if fm_state != login_session["state"]:
                abort(401)
            if fm_email == "" or fm_email_cnf == "":
                has_error = True
                errors["err_fields"] = "Please fill in all fields."
            if not valid_email(fm_email):
                has_error = True
                errors["err_email"] = "Your email is not valid."
            if fm_email != fm_email_cnf:
                has_error = True
                errors["err_cnf"] = "Mismatched email fields."

            if has_error is True:
                state = login_session["state"]
                return redirect(url_for("bp_login.user_settings", STATE=state,
                                        MSG=msg, USERNAME=user.username,
                                        EMAIL=fm_email, USERID=user.id,
                                        PUBLIC=user.public, PROVIDER=provider,
                                        ERRORS=errors), code=302)
            else:
                user.email = fm_email
                login_session["email"] = fm_email

                # If user set page to private
                if fm_yn == "N":
                    user.public = False

                flash("You have successfully updated your settings.")
                return redirect(url_for("bp_main.welcome"), code=302)
        else:
            state = login_session["state"] = gen_csrf_token()
            return render_template("settings.html", STATE=state, MSG=msg,
                                   USERNAME=user.username, EMAIL=user.email,
                                   USERID=user.id, PUBLIC=user.public,
                                   PROVIDER=provider, ERRORS={})

    else:
        if request.method == "POST":
            fm_state = request.form["csrf-token"]
            if fm_state != login_session["state"]:
                abort(401)

            has_error = False
            errors = {}
            fm_username = request.form["fm_username"]
            fm_email = request.form["fm_email"]
            fm_email_cnf = request.form["fm_email_cnf"]
            fm_passd = request.form["fm_passd"]
            fm_passd_cnf = request.form["fm_passd_cnf"]
            fm_yn = request.form["fm-yn"]

            skip_username = skip_email = skip_passd = False
            empty_count = 0

            if fm_username == "":
                skip_username = True
                empty_count += 1
            if fm_email == "" and fm_email_cnf == "":
                skip_email = True
                empty_count += 1
            if fm_passd == "" and fm_passd_cnf == "":
                skip_passd = True
                empty_count += 1

            if skip_username is False and not valid_username(fm_username):
                has_error = True
                msg = ("Username must be between 7 and 20 alphanumeric "
                       "characters. Underscores are permitted.")
                errors["err_username"] = msg
            if skip_email is False and not valid_email(fm_email):
                has_error = True
                errors["err_email"] = "Your email is not valid."
            if skip_passd is False and not valid_password(fm_passd):
                has_error = True
                msg = "Password should be between 12 and 24 characters long."
                errors["pass_len"] = msg
            if (fm_email != fm_email_cnf) or (fm_passd != fm_passd_cnf):
                has_error = True
                errors["err_cnf"] = "Mismatched email or password."

            if has_error is True:
                state = login_session["state"]
                return render_template("signup.html", STATE=state, MSG="",
                                       USERNAME=fm_username, EMAIL=fm_email,
                                       EMAIL_CNF=fm_email_cnf, PASSD=fm_passd,
                                       PASSD_CNF=fm_passd_cnf, USERID=user.id,
                                       PUBLIC=user.public, PROVIDER=provider,
                                       ERRORS=errors)
            elif empty_count == 3:
                flash("No account changes made.")
                return redirect(url_for("bp_main.welcome"), code=302)
            else:
                user.username = fm_username
                user.email = fm_email

                if skip_passd is False:
                    user.hash_password(fm_passd)

                login_session["username"] = user.username
                login_session["email"] = user.email

                flash("You have successfully updated your settings.")
                return redirect(url_for("bp_main.welcome"), code=302)
        else:
            state = login_session["state"] = gen_csrf_token()
            return render_template("settings.html", STATE=state, MSG="",
                                   USERNAME=user.username, EMAIL=user.email,
                                   EMAIL_CNF=user.email, PASSD="",
                                   PASSD_CNF="", USERID=user.id,
                                   PUBLIC=user.public,
                                   PROVIDER=provider, ERRORS={})


@bp_login.route("/login", methods=["GET", "POST"])
def login():
    """Handler for direct application login."""

    # Check if client has cookies enabled
    if "state" not in login_session:
        msg = ("<strong>Cannot run login page. Please make sure you have "
               "cookies enabled.</strong>")
        response = make_response(msg, 401)
        return response

    if request.method == "POST":
        fm_state = request.form["csrf-token"]
        if fm_state != login_session["state"]:
            abort(401)

        fm_email = request.form["fm_email"]
        fm_passd = request.form["fm_passd"]

        try:
            user = session.query(User).filter_by(email=fm_email).one()
        except NoResultFound:
            msg = ("<strong>There is no user registered with that "
                   "email.</strong")
            response = make_response(msg, 404)
            return response

        if user.verify_password(fm_passd) is True:
            login_session["provider"] = "catalog"
            login_session["user_id"] = user.id
            login_session["username"] = user.username
            login_session["email"] = user.email
            login_session["picture"] = None
            login_session["access_token"] = None
            flash("You succesfully logged in.")
            return redirect(url_for("bp_main.welcome"), code=302)
        else:
            flash("Incorrect password.")
            return redirect(url_for("bp_main.welcome"), code=302)


@bp_login.route("/register-oauth", methods=["GET", "POST"])
def register_oauth():
    """Handler for 3rd-party registration confirmation screen."""

    if "username" not in login_session:
        abort(401)

    if request.method == "POST":
        fm_state = request.form["csrf-token"]
        if fm_state != login_session["state"]:
            abort(401)

        fm_yesno = request.form["fm-yn"]

        if fm_yesno == "N":
            login_session["user_id"] = None
            purge_session()
            flash("Cancelled registration.")
            return redirect(url_for("bp_main.welcome"), code=302)

        email = login_session["email"]

        if not valid_email(email):
            login_session["user_id"] = None
            purge_session()
            flash("Invalid email. Operation aborted.")
            return redirect(url_for("bp_main.welcome"), code=302)
        else:
            user = create_user(login_session)
            login_session["user_id"] = user.id
            username = login_session["username"]
            flash("You are now logged in as {}".format(username))
            return redirect(url_for("bp_main.welcome"), code=302)
    else:
        state = login_session["state"] = gen_csrf_token()
        provider = login_session["provider"]

        if provider == "google":
            msg = "Linking to Google Plus"
        if provider == "facebook":
            msg = "Linking to Facebook"
        if provider == "twitter":
            msg = "Linking to Twitter"

        return render_template("register_oauth.html", MSG=msg, STATE=state,
                               GPL_ID=GPL_APP_ID, FB_ID=FB_APP_ID)


@bp_login.route("/connect_gpl", methods=["POST"])
def connect_gpl():
    """Callback for client-site Google Plus OAuth login."""

    client_id = GPL_CLT_ID

    # Checks integrity of state value generated at login()
    # This guards against cross-site forgery attacks
    if request.args.get("state") != login_session["state"]:
        abort(401)

    # Grabs the one-time use code sent from from client
    code = request.data

    # Exchanging the one-time code to get credentials
    try:
        oauth_flow = (OAuth2WebServerFlow(
            client_id=GPL_CLT_ID, client_secret=GPL_SEC, scope="",
            redirect_uri=GPL_RED_URI))
        oauth_flow.redirect_uri = "postmessage"
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        msg = "Failed to upgrade the authorization code."
        response = make_response(jsonify(response=msg), 401)
        return response

    # Pass as parameter to gain user account authorization
    access_token = credentials.access_token
    auth_url = ("https://www.googleapis.com/oauth2/v1/tokeninfo?"
                "access_token={}".format(access_token))
    auth_data = requests.get(auth_url)
    auth_obj = json.loads(auth_data.text)

    # Error and token checks
    if "error" in auth_obj.keys():
        msg = auth_obj["error"]
        response = make_response(jsonify(response=msg), 500)
        return response

    gplus_id = credentials.id_token["sub"]

    if auth_obj["user_id"] != gplus_id:
        msg = "Token's user ID doesn't match given user ID."
        response = make_response(jsonify(response=msg), 401)
        return response

    if auth_obj["issued_to"] != client_id:
        msg = "Token's client ID does not match app's."
        response = make_response(jsonify(response=msg), 401)
        return response

    stored_credentials = login_session.get("credentials")
    stored_gplus_id = login_session.get("gplus_id")

    if stored_credentials is not None and gplus_id == stored_gplus_id:
        flash("Current user is already connected.")
        return redirect(url_for("bp_main.welcome"), code=302)

    credentials = login_session["access_token"] = credentials.access_token
    login_session["gplus_id"] = gplus_id
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {"access_token": credentials, "alt": "json"}
    user_data = requests.get(userinfo_url, params=params)

    # Extract data
    user_data = json.loads(user_data.text)

    # Add provider for disconnect
    login_session["provider"] = "google"
    name = login_session["username"] = user_data["name"]
    picture = login_session["picture"] = user_data["picture"]
    email = login_session["email"] = user_data["email"]
    user_id = get_user_id(email)

    if user_id is None:
        redirect_url = url_for("bp_login.register_oauth")
    else:
        redirect_url = url_for("bp_main.welcome")
        flash("You are now logged in as {}".format(name))
        login_session["user_id"] = user_id

    response = make_response(jsonify(name=name, pic_url=picture,
                                     redirect_url=redirect_url), 200)
    return response


@bp_login.route("/connect_fb", methods=["POST"])
def connect_fb():
    """Callback for client-site Facebook OAuth login."""

    if request.args.get("state") != login_session["state"]:
        abort(401)

    client_id = FB_APP_ID
    client_secret = FB_SEC

    exchange_token = request.data

    auth_url = ("https://graph.facebook.com/v2.9/oauth/access_token?"
                "grant_type=fb_exchange_token&client_id={}&client_secret={}"
                "&fb_exchange_token={}"
                .format(client_id, client_secret, exchange_token))

    auth_data = requests.get(auth_url)
    auth_obj = json.loads(auth_data.text)
    token = auth_obj["access_token"]
    user_url = ("https://graph.facebook.com/v2.9/me?access_token={}"
                "&fields=name,id,email".format(token))
    user_data = requests.get(user_url)
    user_obj = json.loads(user_data.text)

    login_session["provider"] = "facebook"
    name = login_session["username"] = user_obj["name"]
    email = login_session["email"] = user_obj["email"]
    login_session["facebook_id"] = user_obj["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session["access_token"] = token

    pic_url = ("https://graph.facebook.com/v2.9/me/picture?access_token={}"
               "&redirect=0&height=200&width=200").format(token)
    pic_data = requests.get(pic_url)
    pic_obj = json.loads(pic_data.text)

    picture = login_session["picture"] = pic_obj["data"]["url"]
    user_id = get_user_id(email)

    if user_id is None:
        redirect_url = url_for("bp_login.register_oauth")
    else:
        redirect_url = url_for("bp_main.welcome")
        flash("You are now logged in as {}".format(name))
        login_session["user_id"] = user_id

    response = (make_response(jsonify(name=name, pic_url=picture,
                                      redirect_url=redirect_url), 200))
    return response


def auth_request(endpoint, method, fname="", body=""):
    """Builds a signed token for making requests to Twitter API.
    Uses python-oauth2 (https://github.com/joestump/python-oauth2)
    Args:
        endpoint (str): Endpoint for Twitter API service.
        method (str): HTTP action verb.
        fname (str): Function-specific conditions ("twt_connect" or
                     "twt_auth").
        body: (str): For Twitter's verifier code.
    """

    state = gen_csrf_token()

    # Grab some values for params and oauth
    consumer_key = TWT_CON_KEY
    consumer_key_sec = TWT_CLT_SEC
    oauth_token = TWT_AXS_TKN
    oauth_token_sec = TWT_TKN_SEC

    # Parameters required to make an authorized Twitter request
    params = {}

    if fname == "connect_twt":
        params["oauth_callback"] = urllib.quote(url_for("bp_login.auth_twt"))

    if fname == "disconnect_twt":
        params["access_token"] = login_session["access_token"]

    params["oauth_consumer_key"] = consumer_key
    params["oauth_nonce"] = base64.b64encode(state)
    params["oauth_timestamp"] = str(int(time.time()))
    params["oauth_token"] = oauth_token
    params["oauth_version"] = "1.0"

    # Create our request, token and consumer objects.
    req = oauth.Request(method="POST", url=endpoint, parameters=params)
    token = oauth.Token(key=oauth_token, secret=oauth_token_sec)
    consumer = oauth.Consumer(key=consumer_key, secret=consumer_key_sec)

    # Sign the request to get oauth_signature and oauth_signature parameters
    # Using oauth simplifies the cumbersome process of creating a signature
    # https://dev.twitter.com/oauth/overview/creating-signatures
    signature_method = oauth.SignatureMethod_HMAC_SHA1()
    req.sign_request(signature_method, consumer, token)

    # Get the key values from the request object and sort them
    # OAuth spec says to sort lexigraphically
    # The first item is not specified in the Twitter docs,
    # so we exclude it
    req_keys = sorted(req.keys()[1:])

    # Build the required Authorization header value
    # https://dev.twitter.com/oauth/overview/authorizing-requests
    auth_header = "OAuth "

    for k in req_keys:
        val = urllib.quote(req[k])
        k = urllib.quote(k)
        auth_header += k
        auth_header += '="'
        auth_header += val
        auth_header += '"'

        if k == "oauth_version":
            break
        else:
            auth_header += ", "

    # Need to encode the header data
    header = urllib.urlencode({"Authorization": auth_header})

    client = oauth.Client(consumer, token)
    data = client.request(endpoint, method=method, body=body,
                          headers=header)[1]
    return data


@bp_login.route("/connect_twt", methods=["POST"])
def connect_twt():
    """Called by the client when they click the Twitter login button.

    Details of process: https://dev.twitter.com/web/sign-in/implementing
    """

    # Flask's request holds the Request Context invoked from client side
    # Here we grab the {{STATE}} value from .html
    # http://flask.pocoo.org/docs/0.12/api/#flask.Request
    if request.args.get("state") != login_session["state"]:
        msg = "Invalid state parameter."
        response = make_response(jsonify(response=msg), 401)
        return response

    # Request token endpoint
    request_token_url = "https://api.twitter.com/oauth/request_token"

    # Endpoint for authorization (permissions) page
    authenticate_url = "https://api.twitter.com/oauth/authenticate"

    # Execute signed request
    token_data = auth_request(request_token_url, "POST", "connect_twt")

    # https://docs.python.org/2/library/urlparse.html?highlight=parse_qs#urlparse.parse_qs
    token_dic = dict(urlparse.parse_qsl(token_data))

    if ("oauth_callback_confirmed" in token_dic.keys() and
            token_dic["oauth_callback_confirmed"] == "true"):
        oauth_token = token_dic["oauth_token"]

        # Store for future verification purposes
        login_session["access_token"] = oauth_token

        # Now with the authorized request made, we can use the oauth_token
        # and send the redirect url to the authorization page to client
        result = requests.get(authenticate_url,
                              params={"oauth_token": oauth_token})

        # http://docs.python-requests.org/en/latest/api/
        # Return the redirect url for authenticate page
        # response.headers["Content-Type"] = "application/json"
        # WARNING: error code affects how response is treated?
        # 200 = Returns an object
        # 401 = Returns a string

        # response = make_response(json.dumps(result.url), 200)
        # response.headers["Content-Type"] = "application/json"

        response = make_response(jsonify(redirect_url=result.url), 200)
        return response
    else:
        msg = "Error @connect_twt -- Could not authenticate you."
        response = make_response(jsonify(response=msg), 401)
        return response


@bp_login.route("/auth_twt", methods=["GET"])
def auth_twt():
    """Callback for Twitter authorization to get an access token"""

    # Get the oauth_token from Twitter
    oauth_token = request.args.get("oauth_token")

    # Check that OAuth request tokens match
    if oauth_token == login_session["access_token"]:
        access_token_url = "https://api.twitter.com/oauth/access_token"
        oauth_verifier = request.args.get("oauth_verifier")
        req_body = "oauth_verifier={}".format(oauth_verifier)

        # Keep OAuth token secret for future authenticated requests
        oauth_token_secret = request.args.get("oauth_token_secret")
        login_session["twt_token_secret"] = oauth_token_secret

        auth_request(access_token_url, "GET", "auth_twt", req_body)
        user_cred_url = ("https://api.twitter.com/1.1/account/"
                         "verify_credentials.json?include_email=true")

        user_data = json.loads(auth_request(user_cred_url, "GET"))

        # Save for current session
        name = login_session["username"] = user_data["name"]
        email = login_session["email"] = user_data["email"]
        login_session["picture"] = user_data["profile_image_url"]
        login_session["provider"] = "twitter"
        user_id = get_user_id(email)

        if user_id is None:
            return redirect(url_for("bp_login.register_oauth"), code=302)
        else:
            login_session["user_id"] = user_id
            flash("You are now logged in as {}".format(name))
            return redirect(url_for("bp_main.welcome"), code=302)
    else:
        msg = "Error @connect_twt -- Could not authenticate you."
        response = make_response(jsonify(response=msg), 401)
        return response


@bp_login.route("/disconnect")
def disconnect():
    """Handler for logging out."""

    if "username" in login_session:
        purge_session()
        flash("You have successfully been logged out.")
        return redirect(url_for("bp_main.welcome"), code=302)
    else:
        flash("You were not logged in.")
        return redirect(url_for("bp_main.welcome"), code=302)
