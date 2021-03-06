mod_authnz_persona is a module for Apache 2.0 or later that allows you to
quickly add Persona authentication to a site hosted with Apache.

# Installation

First, install the dependencies:

* apache 2.2 or later
* libcurl 7.10.8 or later (for remote verification)
* yajl 2.0 or later (for JSON parsing)

On Red Hat-derivative distributions, this might help:

```
yum install httpd httpd-devel curl-devel cmake
wget http://fedora.mirror.nexicom.net/linux/development/rawhide/source/SRPMS/y/yajl-2.0.4-3.fc20.src.rpm
rpmbuild --rebuild yajl-*.src.rpm
sudo yum install ~/rpmbuild/RPMS/`uname -i`/yajl-*.rpm
```

(CMake is a build-time yajl dependency.)

Then, clone the source and build:

```
git clone https://github.com/mozilla/mod_authnz_persona.git
cd mod_authnz_persona
make
sudo make install
```

(This assumes apxs is behaving properly on your system; set the
APXS_PATH variable to your apxs or apxs2 as appropriate.)

# Configuration

Configure the module:

    LoadModule authnz_persona_module modules/mod_authnz_persona.so

    <Location />
       AuthType Persona
       Require valid-user
       # Or, require users with host/IdP example.com:
       # Require persona-idp example.com
       # Or, require specific users (requires mod_authz_user)
       # Require user user@example.com
    </Location>

This will cause the module to require Persona authentication for all requests
to the server.

# Features

* **zero configuration** - The module is designed with reasonable defaults, so
  you can simply drop it in.
* **automatic re-auth** - The module is designed to use session cookies and
  automatically re-authenticate.

# How it works

The module works by intercepting requests bound for protected resources, and
checking for the presence of a session cookie.

If the cookie is not found, the user agent is served an HTML document that
presents a Persona login page.

Upon successful authentication with Persona, this page will send a request to
the server with a Persona assertion in an HTTP header. The module, upon
detecting no cookie is present, will look for this header, validate the
assertion, and set a short session cookie.

The authentication page will then reload the desired resource.

# Further configuration settings

* `AuthPersonaServerSecret`:
  A secret that will be used to sign cookies. Must be set in a server or
  VirtualHost context. If not provided, upon server start a secret will be
  generated automatically. Given re-authentication is automatic, it is only
  required to set a cookie secret if your application is hosted on multiple
  load-balanced Apache servers.

* `Require persona-idp`:
  Only allow users with email addresses backed by the given Identity Provider.
  Note that this will often, but not necessarily, be the host part of the
  verified email address, in the case of email addresses backed by a secondary
  IdP (like the fallback IdP or a bridging IdP).
