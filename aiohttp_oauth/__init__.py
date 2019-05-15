import uuid
import os

from aiohttp import web
from aiohttp_session import get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp.frozenlist import FrozenList

from .auth import BadAttemptError

DEFAULT_OAUTH_URL = '/auth/oauth_callback'


async def default_auth_header_handler(request):
    return None


class Authenticator:

    def __init__(self, handler, *,
                 auth_callback=None,
                 oauth_url=None,
                 whitelist_handlers=None,
                 oauth_handler=None,
                 auth_header_handler=None,
                 **kwargs):
        self.handler = handler
        self.auth_callback = auth_callback
        self.oauth_url = oauth_url or DEFAULT_OAUTH_URL
        if whitelist_handlers is None:
            whitelist_handlers = []
        self.whitelist_handlers = whitelist_handlers
        if oauth_handler is None:
            oauth_handler = _get_auth_handler(url=self.oauth_url, **kwargs)
        self.oauth_handler = oauth_handler
        if auth_header_handler is None:
            auth_header_handler = default_auth_header_handler
        self.auth_header_handler = auth_header_handler

    async def __call__(self, request, *args, **kwargs):
        # We're passing request twice here as
        # this allows custom implementations to override all
        # arguments passed to a view, for example if your view
        # signature is (something, request) you may call:
        # await self.auth_handler(
        #   request, something, request, *args, **kwargs)
        # and the handler will be called with that signature.
        return await self.auth_handler(request, request, *args, **kwargs)

    async def handle_oauth_callback(self, request, session):
        oauth_handler = self.oauth_handler
        auth_callback = self.auth_callback
        state = oauth_handler.get_state_code(request)
        if session.pop('auth_state_id') != state:
            return web.HTTPForbidden(reason='Bad auth state')

        user = await oauth_handler.handle_oauth_callback(
            request,
            session)

        if auth_callback:
            await auth_callback(user)

        location = session.pop('desired_location')
        session['User'] = user
        return web.HTTPFound(location)

    async def start_authentication(self, request, session):
        oauth_handler = self.oauth_handler
        state = str(uuid.uuid4())
        session['auth_state_id'] = state
        session['desired_location'] = request.path_qs

        try:
            redirect_url = await oauth_handler.get_oauth_url(
                request,
                session,
                state,
            )
        except BadAttemptError as e:
            return web.HTTPForbidden(reason=str(e))

        return web.HTTPFound(redirect_url)

    async def auth_handler(self, request, *args, **kwargs):
        """ The auth flow starts here in this method """
        handler = self.handler
        auth_header_handler = self.auth_header_handler
        whitelist_handlers = self.whitelist_handlers
        auth_url = self.auth_url

        session = await get_session(request)

        if request.headers.get('Authorization'):
            user = await auth_header_handler(request)
            if user is None:
                return web.HTTPUnauthorized()
        else:
            user = session.get('User')

        if user:  # already authenticated
            request['user'] = user
            return await handler(*args, **kwargs)

        final_handler = request.match_info.route.handler
        if final_handler in whitelist_handlers:  # dont need auth
            return await handler(*args, **kwargs)

        # Somtimes there is an extra / somewhere, so we strip it out
        path = request.path.replace('//', '/')

        if path == auth_url and \
                session.get('auth_state_id'):
            """Attempting to authenticate"""
            return await self.handle_oauth_callback(request, session)

        if request.path.startswith('/api/'):
            return web.HTTPUnauthorized()

        # handle auth!
        return await self.start_authentication(request, session)


def oauth_middleware(*, auth_callback=None,
                     oauth_url=None,
                     whitelist_handlers=None,
                     oauth_handler=None,
                     auth_header_handler=None,
                     **kwargs):
    async def middleware_factory(app, handler):
        return Authenticator(
            handler,
            auth_callback=auth_callback,
            oauth_url=oauth_url,
            whitelist_handlers=whitelist_handlers,
            oauth_handler=oauth_handler,
            auth_header_handler=auth_header_handler,
        )
    return middleware_factory


def _get_auth_handler(*, url, **kwargs):
    if 'dummy' in kwargs:
        from . import dummy
        return dummy.DummyAuth(url)
    if 'github_id' in kwargs:
        # use github auth
        from . import github
        return github.GithubAuth(id=kwargs['github_id'],
                                 secret=kwargs['github_secret'],
                                 org=kwargs['github_org'])
    if 'google_id' in kwargs:
        from . import google
        return google.GoogleOAuth(
            id=kwargs['google_id'],
            secret=kwargs['google_secret'],
            redirect_uri=kwargs['google_redirect_uri'],
            approved_domains=kwargs['google_approved_domains'])
    if 'gsuite_id' in kwargs:
        from . import gsuite
        return gsuite.GSuiteOAuth(id_=kwargs['gsuite_id'],
                                  secret=kwargs['gsuite_secret'],
                                  redirect_uri=kwargs['gsuite_redirect_uri'],
                                  google_org=kwargs[
                                      'gsuite_org'])
    else:
        raise NotImplementedError('Either you didnt provide correct keyword'
                                  ' args or the Auth you desire '
                                  'is not yet implemented')


def add_oauth_middleware(app,
                         cookie_key=None,
                         cookie_name='aiohttp_oauth',
                         cookie_is_secure=False,
                         **kwargs):
    if cookie_key is None:
        print('creating new cookie secret')
        cookie_key = os.urandom(16).hex()

    app._middlewares = FrozenList([
        session_middleware(
            EncryptedCookieStorage(cookie_key.encode(),
                                   cookie_name=cookie_name,
                                   secure=cookie_is_secure,
                                   max_age=7200)),  # two hours
        oauth_middleware(**kwargs),
    ] + list(app._middlewares))
