# PySock
Python Socket Proxy for Android

~For Intercepting data between Client Server and Modify them
This script works with system libs
So you don't have to install any library

Except you need Python2.7

@author note
Still needs improvent
Fix Some Bugs
etc

this project provide:
*.http proxy server [yes]
*.script injecting [not yet]
*.hostname checking [yes]
*.caching (usually saving pkt) [yes]
*.replacement [yes]
*.SSLStrip support (by default) [yes]
*.Redirect desired Android app [yes]

Some useful HTTP Headers does not supported yet:
*.Proxy-Connection (for HTTP/1.1)


NOTE:
This program does not works if the app uses HSTS (eg Chrome Browser)
You should change the string replacing at line 135 for better work with sslstrip
Response Redirection is not saved yet

Usage:
pyrhon pysock.py <pkg_name>
