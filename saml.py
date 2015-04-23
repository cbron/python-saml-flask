from flask import session, make_response, request, redirect, jsonify, render_template, current_app
from flask.ext.login import logout_user
from flask.views import View
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from urlparse import urlparse

####
# Extension Manager
####

class SamlManager(object):

    def __init__(self, app=None, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.login_callback = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.saml_manager = self #expose for login_from_acs
        app.add_url_rule('/saml/login', view_func=SamlLogin.as_view('login'), endpoint='login')
        app.add_url_rule('/saml/logout', view_func=SamlLogout.as_view('logout'))
        app.add_url_rule('/saml/acs', view_func=SamlACS.as_view('acs'))
        app.add_url_rule('/saml/sls', view_func=SamlSLS.as_view('sls'))

    def login_from_acs(self, callback):
        self.login_callback = callback
        return callback


####
# Views
####


class SamlLogin(View):
    methods = ['GET']
    def dispatch_request(self):
        saml = SamlRequest(request)
        return redirect(saml.sso())


class SamlLogout(View):
    methods = ['GET']
    def dispatch_request(self):
        saml = SamlRequest(request)
        return redirect(saml.slo())


class SamlACS(View):
    methods = ['POST']
    def dispatch_request(self):
        saml = SamlRequest(request)
        return saml.acs()


class SamlSLS(View):
    methods = ['GET', 'POST']
    def dispatch_request(self):
        saml = SamlRequest(request)
        sls_response = saml.sls()
        logout_user()
        if sls_response.get('success_slo'):
            if current_app.config.get('SAML_LOGOUT_PATH'):
                return redirect(current_app.config.get('SAML_LOGOUT_PATH'))
            else:
                return render_template('saml_logout_successful.html')
        else:
            return jsonify(sls_response)


####
# SAML logic
####


class SamlRequest(object):

    def __init__(self, request_data):
        self.request = self.prepare_flask_request(request_data)
        settings_path = current_app.config.get('SAML_SETTINGS_PATH')
        self.auth = OneLogin_Saml2_Auth(self.request, custom_base_path=settings_path)
        self.errors = []
        self.not_auth_warn = False
        self.success_slo = False
        self.attributes = False
        self.logged_in = False

    def serialize(self):
        return dict(
            errors=self.errors,
            not_auth_warn=self.not_auth_warn,
            success_slo=self.success_slo,
            attributes=self.attributes,
            logged_in=self.logged_in
        )

    def prepare_flask_request(self, request_data):
        url_data = urlparse(request_data.url)
        return {
            'http_host': request_data.host,
            'server_port': url_data.port,
            'script_name': request_data.path,
            'get_data': request_data.args.copy(),
            'post_data': request_data.form.copy()
        }

    def sso(self):
        return self.auth.login()

    def slo(self):
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']
        return self.auth.logout(name_id=name_id, session_index=session_index)

    def acs(self):
        self.auth.process_response()
        self.errors = self.auth.get_errors()
        self.not_auth_warn = not self.auth.is_authenticated()
        if len(self.errors) == 0:
            session['samlUserdata'] = self.auth.get_attributes()
            session['samlNameId'] = self.auth.get_nameid()
            session['samlSessionIndex'] = self.auth.get_session_index()
        if 'samlUserdata' in session:
            self.logged_in = True
            if len(session['samlUserdata']) > 0:
                self.attributes = session['samlUserdata'].items()

        attrs = self.serialize()
        return current_app.saml_manager.login_callback(attrs)

    def sls(self):
        dscb = lambda: session.clear()
        url = self.auth.process_slo(delete_session_cb=dscb)
        self.errors = self.auth.get_errors()
        if len(self.errors) == 0:
            if url is not None:
                return url
            else:
                self.success_slo = True
        return self.serialize()

    def generate_metadata(self):
        settings = self.auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers['Content-Type'] = 'text/xml'
        else:
            resp = make_response(errors.join(', '), 500)
        return resp
