# python-saml-flask

python-saml-flask is an abstraction of [python-saml](https://github.com/onelogin/python-saml), to make for quick integration into flask apps (or django with a bit of work).

It is not an official extension, but acts just like one.


## Setup

1. Save saml.py into your app somewhere (in this example its in a folder called lib)
2. Install `flask-login` and `flask-saml`
3. Add instantiation code:

    ```
    #import
    from flask.ext.login import LoginManager
    from lib.saml import SamlManager

    #setup flask-login
    login_manager = LoginManager()
    login_manager.init_app(flask_app)
    login_manager.login_view = '/saml/login'

    #setup saml manager
    saml_manager = SamlManager()
    saml_manager.init_app(flask_app)
    @saml_manager.login_from_acs
    def acs_login(acs):
      # define login logic here depending on idp response
      # should call login_user() and redirect as necessary
      pass
    ```

4. Define `acs_login`
5. Add settings:

    * `SAML_SETTINGS_PATH` - String - Optional
      * otherwise renders 'saml_logout_successful.html' template
    * `SAML_LOGOUT_PATH` - STRING, - Required
      * path to a 'saml' folder which has:
        * settings.json
        * advanced_settings.json
        * a folder named 'certs' with all certs/keys

6. Create Metadata and trade with IDP

    ```
    from lib.saml import SamlRequest
    from flask import request
    @app.route('/saml/metadata')
    def metadata():
      saml = SamlRequest(request)
      return saml.generate_metadata()
    ```

7. Work with your IDP to finalize everything and test it out.


## Contributing

Contributions are welocme! Please follow these steps:

1. Fork this repository
2. Make your changes
3. Submit PR

