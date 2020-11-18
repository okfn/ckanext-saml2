import logging
import re
import urlparse
import uuid
from importlib import import_module

from routes.mapper import SubMapper
from saml2 import BINDING_HTTP_REDIRECT
from saml2.ident import decode as unserialise_nameid
from sqlalchemy import func
from sqlalchemy.sql.expression import or_

import ckantoolkit as toolkit

import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.logic as logic
import ckan.logic.schema as schema
import ckan.model as model
import ckan.plugins as p
from ckan.controllers.user import UserController
from ckan.logic.action.create import _get_random_username_from_email
from ckan.logic.action.delete import user_delete as ckan_user_delete
from ckan.logic.action.update import user_update as ckan_user_update
from ckanext.saml2.config.sp_config import CONFIG as SAML2_CONFIG
from ckanext.saml2.model.saml2_user import SAML2User

if toolkit.check_ckan_version(min_version='2.8.0'):
    from flask import Blueprint
    from ckan.views.user import (
        EditView as UserEditView,
        login as core_login,
    )


log = logging.getLogger('ckanext.saml2')

_ = toolkit._
request = toolkit.request
config = toolkit.config


DELETE_USERS_PERMISSION = 'delete_users'


def _get_native_login_enabled():
    return toolkit.asbool(config.get('saml2.enable_native_login'))


def _take_from_saml_or_user(key, saml_info, data_dict):
    if key in saml_info:
        return saml_info[key][0]
    elif key in data_dict:
        return data_dict[key]
    else:
        raise KeyError('There are no [{}] neither in saml_info nor in data_dict'.format(key))


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


def _ensure_unique_user_name(email):
    localpart = email.split('@')[0]
    cleaned_localpart = re.sub(r'[^\w]', '-', localpart).lower()
    if model.User.get(cleaned_localpart):
        return _get_random_username_from_email(email)
    return cleaned_localpart


@logic.auth_sysadmins_check
@logic.auth_allow_anonymous_access
def user_create(context, data_dict):
    """Deny user creation."""
    msg = toolkit._('Users cannot be created.')
    if _get_native_login_enabled():
        return logic.auth.create.user_create(context, data_dict)
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
@logic.auth_allow_anonymous_access
def user_reset(context, data_dict):
    """Deny user reset."""
    msg = toolkit._('Users cannot reset passwords.')
    if _get_native_login_enabled():
        return logic.auth.get.user_reset(context, data_dict)
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
@logic.auth_allow_anonymous_access
def request_reset(context, data_dict):
    """Deny user reset."""
    msg = toolkit._('Users cannot reset passwords.')
    method = toolkit.request.method
    username = toolkit.request.params.get('user', '')
    if _get_native_login_enabled():
        user = model.User.get(username)
        if method == 'GET' or user is None or (
                method == 'POST' and is_local_user(user)):
            return logic.auth.get.request_reset(context, data_dict)
    return _no_permissions(context, msg)


def user_delete(context, data_dict):
    """Allow user deletion."""
    user = context['auth_user_obj']
    msg = toolkit._('Users cannot remove users')
    return _no_permissions(context, msg)

rememberer_name = None


def delete_cookies():
    """Logout."""
    global rememberer_name
    if rememberer_name is None:
        plugins = toolkit.request.environ['repoze.who.plugins']
        saml_plugin = plugins.get('saml2auth')
        rememberer_name = saml_plugin.rememberer_name
    base.response.delete_cookie(rememberer_name)
    # We seem to end up with an extra cookie so kill this too
    domain = toolkit.request.environ['HTTP_HOST']
    base.response.delete_cookie(rememberer_name, domain='.' + domain)


def is_local_user(userobj):
    """
    Returns True if userobj is not a SAML2 user.

    """
    return True if saml2_get_user_info(userobj.id) is None else False


def assign_default_role(context, user_name):
    """Creates organization member roles according to saml2.default_org
    and saml2.default_role or does nothing if those are not set.

    """
    user_org = config.get('saml2.default_org')
    user_role = config.get('saml2.default_role')
    if user_org and user_role:
        member_dict = {
            'id': user_org,
            'username': user_name,
            'role': user_role
        }
        toolkit.get_action('organization_member_create')(
            context, member_dict)


def get_came_from(relay_state):
    """Returns the original URL requested by the user before
    authentication, parsed from the SAML2 RelayState
    """
    rs_parsed = urlparse.urlparse(relay_state)
    came_from = urlparse.parse_qs(rs_parsed.query).get('came_from', None)
    if came_from is None:
        # No came_from param was supplied to /user/login
        return None
    cf_parsed = urlparse.urlparse(came_from[0])
    # strip scheme and host to prevent redirection to other domains
    came_from = urlparse.urlunparse(('',
                                     '',
                                     cf_parsed.path,
                                     cf_parsed.params,
                                     cf_parsed.query,
                                     cf_parsed.fragment))
    log.debug('came_from = %s', came_from)
    return came_from.encode('utf8')


def saml2_get_userid_by_name_id(id):
    user_info = model.Session.query(SAML2User).\
        filter(SAML2User.name_id == id).first()
    return user_info.id if user_info is not None else user_info


def saml2_get_user_name_id(id):
    user_info = saml2_get_user_info(id)
    return user_info if user_info is None else user_info[0].name_id


def saml2_get_user_info(id):
    query = model.Session.query(SAML2User, model.User).\
        join(model.User, model.User.id == SAML2User.id).\
        filter(or_(func.lower(SAML2User.name_id) == func.lower(id),
                   SAML2User.id == id,
                   model.User.name == id)).first()
    return query


def saml2_user_delete(context, data_dict):
    if not data_dict.get('id') and data_dict.get('nameid'):
            saml2_user_id = saml2_get_userid_by_name_id(data_dict['nameid'])
            if saml2_user_id is not None:
                data_dict['id'] = saml2_user_id
            else:
                raise logic.NotFound('NameID "{id}" was not found.'.format(
                                            id=data_dict['nameid']))
    ckan_user_delete(context, data_dict)


def saml2_set_context_variables_after_check_for_user_update(id):
    c = toolkit.c
    c.allow_user_change = p.toolkit.asbool(
        config.get('saml2.allow_user_changes', False))


def saml2_user_update(context, data_dict):
    if data_dict.get('password1', '') != '' or data_dict.get('password2', '') != '':
        raise logic.ValidationError({'password': [
            "This field cannot be modified."]})

    id = logic.get_or_bust(data_dict, 'id')
    name_id = saml2_get_user_name_id(id)
    if name_id is not None:
        allow_user_change = toolkit.asbool(
            config.get('saml2.allow_user_changes', False))

        if not allow_user_change:
            raise logic.ValidationError({'error': [
                "User accounts managed by Single Sign-On can't be modified"]})

    return ckan_user_update(context, data_dict)


class Saml2Plugin(p.SingletonPlugin):
    """SAML2 plugin."""

    p.implements(p.IAuthenticator, inherit=True)
    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IAuthFunctions, inherit=True)
    p.implements(p.IConfigurer, inherit=True)
    p.implements(p.IConfigurable)
    p.implements(p.ITemplateHelpers)
    p.implements(p.IActions)
    if toolkit.check_ckan_version(min_version='2.8.0'):
        p.implements(p.IBlueprint)

    def update_config(self, config):
        """Update environment config."""
        toolkit.add_resource('fanstatic', 'ckanext-saml2')
        toolkit.add_template_directory(config, 'templates')

    def make_mapping(self, key, config):
        """Map user data from .ini file."""
        data = config.get(key)
        mapping = {}
        for item in data.split():
            bits = item.split('~')
            mapping[bits[0]] = bits[1]
        return mapping

    def configure(self, config):
        """Apply mapping."""
        self.user_mapping = self.make_mapping('saml2.user_mapping', config)
        m = self.make_mapping('saml2.organization_mapping', config)
        self.organization_mapping = m

    def before_map(self, map):
        """Custom routes for Pylons based controller (CKAN<=2.7)"""

        if p.toolkit.check_ckan_version(max_version='2.8.0'):
            with SubMapper(
                    map, controller='ckanext.saml2.plugin:Saml2Controller') as m:
                m.connect('staff_login', '/service/login', action='staff_login')
                m.connect(
                    'saml2_user_edit', '/user/edit/{id:.*}', action='edit',
                    ckan_icon='cog')
        return map

    def get_blueprint(self):
        blueprint = Blueprint('saml2', self.__module__)

        blueprint.add_url_rule(rule='/service/login', view_func=native_login)

        _saml2_edit_view = Saml2UserEditView.as_view(str(u'edit'))
        blueprint.add_url_rule(
            rule=u'/user/edit/<id>', view_func=_saml2_edit_view)

        return blueprint

    def make_password(self):
        """Create a hard to guess password."""
        out = ''
        for n in xrange(8):
            out += str(uuid.uuid4())
        return out

    def identify(self):
        """
        Work around saml2 authorization.

        c.user contains the saml2 id of the logged in user we need to
        convert this to represent the ckan user.
        """

        # Can we find the user?
        c = toolkit.c
        environ = toolkit.request.environ

        name_id = environ.get('REMOTE_USER', '')
        log.debug("REMOTE_USER = \"{0}\"".format(name_id))

        name_id = unserialise_nameid(name_id).text
        if not name_id:
            log.info('Ignoring REMOTE_USER - does not look like a NameID')
            return
        log.debug('NameId: %s' % (name_id))

        saml2_user_info = saml2_get_user_info(name_id)
        if saml2_user_info is not None:
            c.user = saml2_user_info[1].name

        log.debug("repoze.who.identity = {0}".format(dict(environ["repoze.who.identity"])))

        # get the actual user info from the saml2auth client
        try:
            saml_info = environ["repoze.who.identity"]["user"]
        except KeyError:
            # This is a request in an existing session so no need to provision
            # an account, set c.userobj and return
            c.userobj = model.User.get(c.user)
            if c.userobj is not None:
                c.user = c.userobj.name
            return

        try:
            # Update the user account from the authentication response
            # every time
            c.userobj = self._create_or_update_user(c.user, saml_info, name_id)
            c.user = c.userobj.name
        except Exception as e:
            log.error(
                "Couldn't create or update user account ID:%s", c.user)
            log.error("Error %s", e)
            c.user = None
            return

        # Update user's organization memberships either via the
        # configured saml2.org_converter function or the legacy GSA
        # conversion
        update_membership = False

        org_roles = {}
        # import the configured function for converting a SAML
        # attribute to a dict for create_organization()
        org_mapper_config = config.get('saml2.organization_mapper', None)
        get_org_roles = None
        if org_mapper_config is not None:
            try:
                module_name, function_name = org_mapper_config.split(':', 2)
                module = import_module(module_name)
                get_org_roles = getattr(module, function_name)
            except Exception as e:
                log.error("Couldn't import saml2.organization_mapper: %s", org_mapper_config)
                log.error("Error: %s", e)

        if get_org_roles is not None:
            update_membership = True
            org_roles = get_org_roles(saml_info)

        elif 'name' in self.organization_mapping and self.organization_mapping['name'] in saml_info:
            # Backwards compatibility for the original implementation
            # at
            # https://github.com/GSA/ckanext-saml2/blob/25521bdbb3728fe8b6532184b8b922d9fca4a0a0/ckanext/saml2/plugin.py
            org = {}
            # apply mapping
            self.update_data_dict(org, self.organization_mapping, saml_info)
            org_name = org['name']
            org_roles[org_name] = {
                'capacity': 'editor' if org['field_type_of_user'][0] == 'Publisher' else 'member',
                'data': org,
            }
            update_membership = True

        disable_organization_membership = config.get('saml2.disable_organization_membership', False)
        if disable_organization_membership:
            update_membership = False

        if update_membership:
            self.update_organization_membership(org_roles)

        # Redirect the user to the URL they requested before
        # authentication. Ideally this would happen in the controller
        # of the assertion consumer service but in lieu of one
        # existing this location seems reliable.
        request = toolkit.request
        if request.method == 'POST':
            relay_state = request.POST.get('RelayState', None)
            if relay_state:
                came_from = get_came_from(relay_state)
                if came_from:
                    h.redirect_to(came_from)

            redirect_after_login = config.get('saml2.redirect_after_login', '/dashboard')
            h.redirect_to(redirect_after_login)

    def _create_or_update_user(self, user_name, saml_info, name_id):
        """Create or update the subject's user account and return the user
        object"""
        data_dict = {}
        user_schema = schema.default_update_user_schema()

        is_new_user = False
        userobj = model.User.get(user_name)
        if userobj is None:
            is_new_user = True
            user_schema = schema.default_user_schema()
        else:
            if userobj.is_deleted():
                # If account exists and is deleted, reactivate it. Assumes
                # only the IAM driving the IdP will deprovision user
                # accounts and wouldn't allow a user to authenticate for
                # this app if they shouldn't have access.
                log.debug("Reactivating user")
                userobj.activate()
                userobj.commit()

            data_dict = toolkit.get_action('user_show')(
                data_dict={'id': user_name, })

        # Merge SAML assertions into data_dict according to
        # user_mapping
        update_user = self.update_data_dict(data_dict,
                                            self.user_mapping,
                                            saml_info)

        # Remove validation of the values from id and name fields
        user_schema['id'] = [toolkit.get_validator('not_empty')]
        user_schema['name'] = [toolkit.get_validator('not_empty')]
        context = {'schema': user_schema, 'ignore_auth': True}
        if is_new_user:
            email = _take_from_saml_or_user('email', saml_info, data_dict)
            new_user_username = _ensure_unique_user_name(email)
            data_dict['name'] = new_user_username
            data_dict['id'] = unicode(uuid.uuid4())
            log.debug("Creating user: %s", data_dict)
            data_dict['password'] = self.make_password()
            new_user = toolkit.get_action('user_create')(context, data_dict)
            assign_default_role(context, new_user_username)
            model.Session.add(SAML2User(id=new_user['id'],
                                        name_id=name_id))
            model.Session.commit()
            return model.User.get(new_user_username)
        elif update_user:
            allow_user_change = toolkit.asbool(
                config.get('saml2.allow_user_changes', False))
            if allow_user_change:
                log.debug("Updating user: %s", data_dict)
                toolkit.get_action('user_update')(context, data_dict)
        return model.User.get(user_name)

    def update_organization_membership(self, org_roles):
        """Create organization using mapping.

        org_roles is a dict whose keys are organization IDs, and
        values are a dict containing 'capacity' and 'data', e.g.,

        org_roles = {
            'org1': {
                'capacity': 'member',
                'data': {
                    'id': 'org1',
                    'description': 'A fun organization',
                    ...
                },
            },
            ...
        }

        """

        create_orgs = toolkit.asbool(
            config.get('saml2.create_missing_orgs', False))
        remove_user_from_orgs = toolkit.asbool(
            config.get('saml2.rvm_users_from_orgs', True))
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c

        # Create missing organisations
        if create_orgs:
            for org_id in org_roles.keys():
                org = model.Group.get(org_id)

                if not org:
                    context = {'user': site_user['name']}
                    data_dict = {
                        'id': org_id,
                    }
                    data_dict.update(org_roles[org_id].get('data', {}))
                    try:
                        toolkit.get_action('organization_create')(
                            context, data_dict)
                    except logic.ValidationError, e:
                        log.error("Couldn't create organization: %s", org_id)
                        log.error("Organization data was: %s", data_dict)
                        log.error("Error: %s", e)

        # Create or delete membership according to org_roles
        all_orgs = toolkit.get_action('organization_list')(context, {})
        for org_id in all_orgs:
            org = model.Group.get(org_id)

            # skip to next if the organisation doesn't exist
            if org is None:
                continue

            member_dict = {
                'id': org_id,
                'object': c.userobj.id,
                'object_type': 'user',
            }
            member_context = {
                'user': site_user['name'],
                'ignore_auth': True,
            }
            if org_id in org_roles:
                # add membership
                member_dict['capacity'] = org_roles[org_id]['capacity']
                toolkit.get_action('member_create')(
                    member_context, member_dict)
            else:
                if remove_user_from_orgs:
                    # delete membership
                    toolkit.get_action('member_delete')(
                        member_context, member_dict)

    def update_data_dict(self, data_dict, mapping, saml_info):
        """Updates data_dict with values from saml_info according to
        mapping. Returns the number of items changes."""
        count_modified = 0
        for field in mapping:
            value = saml_info.get(mapping[field])
            if value:
                # If list get first value
                if isinstance(value, list):
                    value = value[0]
                if not field.startswith('extras:'):
                    if data_dict.get(field) != value:
                        data_dict[field] = value
                        count_modified += 1
                else:
                    if 'extras' not in data_dict:
                        data_dict['extras'] = []
                    data_dict['extras'].append(
                        dict(key=field[7:], value=value))
                    count_modified += 1
        return count_modified

    def login(self):
        """
        Login definition.

        We can be here either because we are requesting a login (no user)
        or we have just been logged in.
        """
        c = toolkit.c
        if not c.user:
            try:
                if toolkit.c.action in (
                        'staff_login', 'native_login', 'logged_in'):
                    return
            except AttributeError:
                pass
            if _get_native_login_enabled():
                c.sso_button_text = config.get('saml2.login_form_sso_text')
                if toolkit.request.params.get('type') != 'sso':
                    came_from = toolkit.request.params.get('came_from', None)
                    if came_from:
                        c.came_from = came_from
                    return
            return base.abort(401)

        if toolkit.check_ckan_version(min_version='2.8.0'):
            return h.redirect_to('dashboard.index')
        else:
            h.redirect_to(controller='user', action='dashboard')

    def _clear_cookies_and_redirect(self, cookie_name, location=None):

        domain = toolkit.request.environ['HTTP_HOST']

        if not location:
            location = toolkit.url_for(controller='home', action='index')

        if toolkit.check_ckan_version(min_version='2.8.0'):
            # CKAN >= 2.8, request served by Flask

            resp = h.redirect_to(location)
            resp.set_cookie(cookie_name, domain='.' + domain, expires=0)
            resp.set_cookie(cookie_name, expires=0)

            return resp
        else:
            # CKAN < 2.8, request served by Pylons
            base.response.delete_cookie(cookie_name, domain='.' + domain)
            base.response.delete_cookie(cookie_name)
            h.redirect_to(location)

    def logout(self):
        """Logout definition."""
        environ = toolkit.request.environ
        userobj = toolkit.c.userobj

        sp_initiates_slo = toolkit.asbool(config.get('saml2.sp_initiates_slo', True))
        if not sp_initiates_slo or userobj and is_local_user(userobj):
            plugins = environ['repoze.who.plugins']
            friendlyform_plugin = plugins.get('friendlyform')
            rememberer = environ['repoze.who.plugins'][friendlyform_plugin.rememberer_name]
            cookie_name = rememberer.cookie_name
            location = h.url_for(controller='home', action='index')

            return self._clear_cookies_and_redirect(cookie_name, location)

        subject_id = environ["repoze.who.identity"]['repoze.who.userid']
        name_id = unserialise_nameid(subject_id)
        client = environ['repoze.who.plugins']["saml2auth"]

        # Taken from saml2.client:global_logout but forces
        # HTTP-Redirect binding.
        entity_ids = SAML2_CONFIG['service']['sp']['idp']
        saml_logout = client.saml_client.do_logout(name_id, entity_ids,
                                                   reason='urn:oasis:names:tc:SAML:2.0:logout:user',
                                                   expire=None, sign=True,
                                                   expected_binding=BINDING_HTTP_REDIRECT,
                                                   sign_alg="rsa-sha256", digest_alg="hmac-sha256")

        cookie_name = environ['repoze.who.plugins'][client.rememberer_name].cookie_name

        # Redirect to send the logout request to the IdP, using the
        # url in saml_logout. Assumes only one IdP will be returned.
        for key in saml_logout.keys():
            location = saml_logout[key][1]['headers'][0][1]
            log.debug("IdP logout URL = {0}".format(location))
            return self._clear_cookies_and_redirect(cookie_name, location)

    def get_auth_functions(self):
        """We need to prevent some actions being authorized."""
        return {
            'user_create': user_create,
            'user_reset': user_reset,
            'user_delete': user_delete,
            'request_reset': request_reset,
        }

    def get_helpers(self):
        return {
            'saml2_get_user_name_id': saml2_get_user_name_id
        }

    def get_actions(self):
        return {
            'user_delete': saml2_user_delete,
            'user_update': saml2_user_update
        }


def native_login():
    return core_login()


class Saml2UserEditView(UserEditView):

    def post(self, id=None):
        saml2_set_context_variables_after_check_for_user_update(id)
        return super(Saml2UserEditView, self).post(id)

    def get(self, id=None, data=None, errors=None, error_summary=None):
        saml2_set_context_variables_after_check_for_user_update(id)
        return super(Saml2UserEditView, self).get(id, data, errors, error_summary)


class Saml2Controller(UserController):
    """SAML2 Controller."""

    def staff_login(self):
        """Default login page for staff members."""
        return self.login()

    def edit(self, id=None, data=None, errors=None, error_summary=None):
        saml2_set_context_variables_after_check_for_user_update(id)
        return super(Saml2Controller, self).edit(id, data, errors, error_summary)
