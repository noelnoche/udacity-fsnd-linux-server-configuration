""""This module contains code for limiting request rates."""

import time
from flask import g, request
from flask import Blueprint, Flask, jsonify
from functools import update_wrapper

# https://redis.io/
from redis import Redis

redis = Redis()

app = Flask(__name__)

bp_rlimit = Blueprint("bp_rlimit", __name__)


class RateLimit(object):

    # Gives key an extra 10s to expire in Redis
    # Badly synchronized clocks between workers and Redis server
    # will not cause issues
    expiration_window = 10

    # key_prefix: A string that keeps track of each request rate limit
    # limit, per: Controls number of allowed requests over a time period
    # send_x_header (bool): Injected in each response header the number of
    # remaining requests before limit is reached
    def __init__(self, key_prefix, limit, per, send_x_headers):

        # Allows to define a time when rate-limit can reset itself
        # This is appended to the key
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers

        # Makes sure we set the expiration every time we increment the key
        # This is in case an exception happens between those lines
        p = redis.pipeline()

        # Increase the value of pipline and set it to expire
        # based on the reset value and expiration window
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    # Calculates remaining requests and returns True when limit reached
    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)


# Retrieves info from g object in Flask
def get_view_rate_limit():
    return getattr(g, "_view_rate_limit", None)


# Notifies the client that they reached their limit
# 429 means too many requests
def on_over_limit(limit):
    return (jsonify({"data": "You hit the rate limit", "error": "429"}), 429)


# Wrap around a decorator
def rate_limiter(limit, per=300, send_x_headers=True,
                 over_limit=on_over_limit,
                 scope_func=lambda: request.remote_addr,
                 key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):

            # key is made by default by remote address and current endpoint
            key = "rate-limit/{}/{}/".format(key_func(), scope_func())

            # Before the function is executed, it increments the rate limit
            # with the help of the RateLimit class and stores an instace on
            # the g object's _view_rate_limit parameter
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit

            # Call over_limit when condition met
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator


# Append the number of remaining requests, the limit for that endpoint
# and time until limit resets in teh header of each request
# This feature can be turned off when send_x_headers is set to False
@bp_rlimit.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add("X-RateLimit-Remaining", str(limit.remaining))
        h.add("X-RateLimit-Limit", str(limit.limit))
        h.add("X-RateLimit-Reset", str(limit.reset))
    return response


# Example added to a route
# Limit is 300 requests per 30 seconds
# @app.route("/rate-limited")
# @rate_limiter(limit=300, per=30 * 1)
# def index():
#     return jsonify({"response":"This is a rate limited response"})

# if __name__ == "__main__":
#     app.secret_key = "super_secret_key"
#     app.debug = True

#     # Using IP addrss as client identifier so rate-limiting
#     # works for non-logged in users
#     app.run(host="0.0.0.0", port=8000)
