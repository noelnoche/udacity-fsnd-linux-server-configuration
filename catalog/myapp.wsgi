"""
Interfaces the Python application to the Apache server under the WSGI standard.

"""

def application(req_environ, start_response):
    import sys

    sys.path.insert(0, "/var/www/catalog/")

    from catalog import app as _application

    return _application(req_environ, start_response)
