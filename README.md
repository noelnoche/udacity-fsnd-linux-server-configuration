Linux Server Configuration
===
<br>


Introduction
---
The focus of this project is to gain better insight into how to set up and configure a secure Apache server to host a Python application that uses Flask, PostgresSQL and SQLAlchemy. The Apache module `mod_wsgi` is used to establish a WSGI compliant interface for hosting the application.  Successful completion of the project requires knowledge and skills in many areas of full-stack development summarized here and detailed in the sections that follow.

+ Ubuntu and Apache file systems
+ Managing Ubuntu applications
+ Command line fluency
+ Altering file permissions and ownership
+ Creating users with limited privileges
+ Setting up SSH-based login
+ Configuring orts and firewall
+ Modifying Apache configuration files
+ Refactoring database models for PostgreSQL
+ Implementing Python code to work with Apache 
+ Setting environment variables for the application


I. Set up a new user with `sudo` status
---
1. Create an Ubuntu instance on Lightsail.
2. Make the public IP address static.
3. Note you will use this IP address to log in from your local terminal later.
4. Connect to the online instance terminal (you are logged in as `ubuntu`).
5. Update and upgrade Ubuntu:
    + `sudo apt-get update`
    + `sudo apt-get upgrade`
6. Add the new user: `sudo adduser { username }`
7. Give the user sudo status:
    + `sudo cp /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/{ username }`
    + `sudo nano /etc/sudoers.d/{ username }`
    + Change `ubuntu` to `{ username }` and save the file.


II. Set up key-based login
---    
1. Download an SSH key pair (`xxx.pem` file) from Lightsail.
2. Create an `.ssh` directory on your local home directory if there isn't one.
3. Change `xxx.pem` permissions and move it into the `.ssh` directory.
    + `sudo chmod 400 xxx.pem/`
    + `mv xxx.pem .ssh`
4. Go to online Ubuntu terminal make an `.ssh` directory for `username`.
    + `sudo cd /home/{ username }`
    + `sudo mkdir .ssh`
    + `sudo chown { username }:{ username } .ssh`
5. Set up the file for holding public RSA keys for `username`.
    + `sudo cp .ssh/authorized_keys /home/{ username }/.ssh/`
    + `cd /home/{ username }/.ssh`
    + `sudo chown { username }:{ username } authorized_keys`
6. Generate a new key pair specifically for `username` on your local machine.
    + `cd` into the `.ssh` directory
    + `ssh-keygen` (creates two files yyy and yyy.pub)
    + Overwrite the key in `username`'s `authorized_keys` file with the one in yyy.pub`.
    + `chmod 400 yyy.pub`
7. Set permissions for the `.ssh` directory and `authorized_keys`:
    + `cd`
    + `chmod 700 .ssh`
    + `chmod 664 authorized_keys`
8. You should now be able to login from your local termial as `ubuntu` or `username`:  
    + `ssh -i .ssh/xxx.pem ubuntu@{ IP address } -p 22`
    + `ssh -i .ssh/yyy { username }@{ IP address } -p 22`


III. Change the SSH port and configure the firewall
---
1. On your local terminal login as `username` or `ubuntu`.
2. Set the new port you will use to securely login:
    + `sudo nano /etc/ssh/sshd_config`
    + Add `Port 2200` under the line `Port 22`
    + `sudo service ssh reload`
3. Set and enable the firewall:
    + `sudo ufw default deny incoming && sudo ufw default allow outgoing`
    + `sudo ufw allow ssh`
    + `sudo ufw allow 2200`
    + `sudo ufw allow http`
    + `sudo ufw allow ntp`
    + `sudo ufw enable`
4. Check the firewall status: `sudo ufw status`
5. Check if the ssh ports are working: `sudo netstat -lnp`
6. In the Lightsail console Networking tab add a custom port for TCP 2200.
7. Make sure port 2200 is not blocked or used on your local machine.
8. Open your local terminal and check if you can login on port 2200:  
    `ssh -i .ssh/{ ssh key file } { username}@{ IP address } -p 2200`
9. If successful, delete Port 22 from `sshd_config` and reload ssh as before.
10. Remove Port 22 from the Lightsail Networking tab.
11. Disable port 22 and confirm the firewall status: `sudo ufw deny 22`


IV. Set up the server
---
1. Install Apache2 and wsgi application handler:
     + `sudo apt-get install apache2`
     + `sudo apt-get install libapache2-mod-wsgi`
2. Go to the default virtual host configuration file directory:  
     `cd /etc/apache2/sites-available`
3. Copy and rename the default configuration file: `cp 000-default conf xxx.conf`
4. Open `xxx.conf` and make the contents look like _fig-a_.
5. Disable the default file and enable `xxx.conf`:
    + `sudo a2dissite 000-default`
    + `sudo a2ensite xxx`
    + `sudo service apache2 reload`
6. Install PostgreSQL, Pip, Flask and SQLAlchemy: 
    + `sudo apt-get install postgresql`
    + `sudo apt-get install python-pip` (`python3-pip` if using Python 3.x).
    + `sudo -H pip install Flask`
    + `sudo -H pip install SQLAlchemy`
7. Check that the local timezone is UTC: `date`
8. If it is not UTC run:
    + `sudo dpkg-reconfigure tzdata`
    + Select `None of the above` and hit Enter
    + Select `UTC` and hit Enter

**_fig-a_**

```shell
<VirtualHost *:80>
	#ServerName www.example.com
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/{ path to app root directory }

	ErrorLog ${APACHE_LOG_DIR}/error.log
	LogLevel info
	CustomLog ${APACHE_LOG_DIR}/access.log combined

    WSGIScriptAlias / /var/www/{ path to xxx.wsgi file }
</VirtualHost>
```


V. Run a test WSGI script
---
1. Disable or delete the default Apache test file in `/var/www/html`.
2. Create the test file in the `/var/www` directory: `sudo nano xxx.wsgi`
3. Copy the test code in _fig-b_.
4. Open a browser at the server's public ip address.
5. `Hello World` will appear on the page.

**_fig-b_**  

```python
def application(environ, start_response):
    status = '200 OK'
    output = 'Hello World!'

    response_headers = [('Content-type', 'text/plain'), ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    return [output]
```

VI. Set up your application
---
1. Install Git (Lightsail Ubuntu instances come with git installed):
    + `sudo apt-get update`
    + `sudo apt-get install git`
2. Go the the `xxx.wsgi` directory.
3. Clone your Python application from GitHub: `sudo git clone { repository url }`
4. Move `xxx.wsgi` into your application root directory.
5. Change the ownership of the application from `root` to `username`:
    + `sudo chown { username } { application folder }`
    + `cd` into the applicaito folder
    + `sudo chown -R { username }:{ username} *`
6. Install application dependencies: `sudo -H pip install { package }`
7. Prepare for a lot of web searching to learn how to implement your application     using `wsgi_mod` module. Some good places to start are listed in the Reference     section.


VII. Set up Cyberduck (optional)
---
1. Your application might require many tweaks to make it work with Apache and      Postgres. Cyberduck (and Filezilla) are programs that allow you to `ssh` to the      server and handle files locally using your favorite code editor. See the reference      section for links to these programs.
2. Install and open Cyberduck.
3. Click "Open Connection".
4. From the top menu change the connection method from FTP to SFTP.
5. Change to port from 22 to 2200.
6. Enter the public IP address and user you want to login as.
7. Select the private key associated with that user and click "Connect".
8. You might get an alert about "Unknown fingerprint". Click "Allow".
9. You should now be logged in the user's home folder.
10. You can edit a file directly from Cyberduck's panel by selecting the file and        clicking "Edit". Note: Before editing, check the file's owner and permissions.         The user you are logged in as must be the owner, or else the file will fail to        upload after you edit and save it.


VIII. Create a database user with limited permissions
---
1. Switch to Postgres's default superuser:  `sudo su - postgres`
2. Create an empty database and a Postgres user (different from system user):
    + `createdb { database_name }`
    + `createuser { username }`
3. Change to the Postgres command shell: `psql`
4. Give that user login and password attributes:  
    `ALTER ROLE { username } WITH LOGIN PASSWORD '{ password }'       VALID UNTIL 'infinity';` 
5. Allow the user to connect to the database:  
    `GRANT CONNECT ON DATABASE { database_name } TO { username };`
6. Generate tables for the database using the new user from your application.      The database name used in the application must match the one you created.     In SQLAlchemy with PostgreSQL, table-mapping has the structure shown      in _fig-c_.   
7. Connect to the database and restrict table privileges of the new user:
    + `\c { database_name };`
    + `REASSIGN OWNED BY { username } TO postgres;`
    + `GRANT SELECT, UPDATE, INSERT, DELETE ON { table1name,          table2name, ...} TO { username };`
    + `GRANT SELECT, USAGE ON ALL SEQUENCES IN SCHEMA public TO          { username };
8. Confirm that table restrictions are in effect: `\z`
9. Exit to the system user: `\q` then `exit`
10. You should now be able to switch to the new user:  
      `psql -U { username } -d { database_name } -h 127.0.0.1 -W`

**_fig-c_**

```python
from sqlalchemy import create_engine
engine = create_engine("postgresql://{ username }:{ password }@{ IP address }/{ database name }")
```


IX. Setting environment variables
---
1. Place your custom environment variables in the `envvars` file located in the      `/etc/apache2` directory.
2. You first need to **completely** shut down the Apache server:
    + `sudo a2dissite xxx`
    + `sudo service apache2 reload`
    + `sudo systemctl stop apache2.service`
    + `sudo service apache2 stop`
3. Open `ennvars`: `sudo nano envvars`
4. Add your environment variables at the bottom of the file in this format:  
    `export MY_VAR="{ secret sfuff }"`
5. Set your variables in the application after instantiating Flask, which itself is       imported into the `xxx.wsgi` script as show in _fig-d_.
6. Restart the server:
    + `sudo service apache2 start`
    + `sudo systemctl start apache2.service`
    + `sudo a2ensite xxx`
    + `sudo service apache2 reload`

**_fig-d_**

```python        
# flask_app.py
import os
from flask import Flask

app = Flask(__name__)

app.secret_key = os.environ["MY_VAR"]
```
```python
# xxx.wsgi
def application(req_environ, start_response):

    from flask_app import app as _application
    
    return _application(req_environ, start_response)
  ```      


Software Links
---
+ [Cyberduck homepage](https://cyberduck.io/?l=en)
+ [FileZilla homepage](https://filezilla-project.org/)
+ [Reverse DNS lookup](https://remote.12dt.com/)


Documentation
---
+ [Apache2 Web Server for Ubuntu](https://help.ubuntu.com/lts/serverguide/httpd.html)
+ [mod_wsgi](http://modwsgi.readthedocs.io/en/develop/index.html)
+ [Ubuntu](http://manpages.ubuntu.com/)
+ [PostgreSQL](https://www.postgresql.org/docs/9.6/static/index.html)
+ [SQLAlchemy](http://docs.sqlalchemy.org/en/latest/contents.html)


Reference
---
+ [About WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface)
+ [Getting started with WSGI](http://lucumr.pocoo.org/2007/5/21/getting-started-with-wsgi/)
+ [mod_wsgi (Apache)](http://flask.pocoo.org/docs/0.12/deploying/mod_wsgi/)
+ [How To Deploy a Flask Application on an Ubuntu VPS](https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps)
+ [How to secure PostgreSQL on an Ubuntu VPS](https://www.digitalocean.com/community/tutorials/how-to-secure-postgresql-on-an-ubuntu-vps)
+ [How To Use Roles and Manage Grant Permissions in PostgreSQL on a VPS](https://www.digitalocean.com/community/tutorials/how-to-use-roles-and-manage-grant-permissions-in-postgresql-on-a-vps--2)
+ [Keep Secret Keys Out With Environment Variables](https://stackoverflow.com/questions/14786072/keep-secret-keys-out-with-environment-variables)
+ [a2ensite / a2dissite](http://manpages.ubuntu.com/manpages/yakkety/man8/a2ensite.8.html#contenttoc0)
+ [Start, restart and stop Apache server](http://www.learn4master.com/programming-language/shell/start-restart-and-stop-apache-on-linux)
