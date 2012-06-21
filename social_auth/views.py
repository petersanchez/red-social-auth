import re
import json
import tweepy
import urllib
import random
import logging
import urllib2
import hashlib
import datetime

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect
from django.views.decorators.cache import never_cache

from social_auth import oauth2
from social_auth import https_connection
from social_auth.forms  import IdentityProviderForm
from social_auth.oauth2 import VerifiedHTTPSConnection
from social_auth.models import SocialUser, IdentityProvider, PROVIDERS

URL_TIMEOUT = getattr(settings, 'SOCIAL_AUTH_URL_TIMEOUT', 15)
FACEBOOK_API_KEY = getattr(settings, 'FACEBOOK_API_KEY', None)
FACEBOOK_API_SECRET = getattr(settings, 'FACEBOOK_API_SECRET', None)
TWITTER_API_KEY = getattr(settings, 'TWITTER_API_KEY', None)
TWITTER_API_SECRET = getattr(settings, 'TWITTER_API_SECRET', None)
GOOGLE_API_SECRET = getattr(settings, 'GOOGLE_API_SECRET', None)
GOOGLE_API_KEY = getattr(settings, 'GOOGLE_API_KEY', None)
TRACKER_NAME = getattr(settings, 'SOCIAL_AUTH_TRACKER_NAME', '_logged_in')


def _build_cache_buster(user):
    now = datetime.datetime.now()
    hash_str = '%s-%i-%s' % (now, user.id, user.username)
    digest = hashlib.sha1(hash_str).hexdigest()
    return ''.join([random.choice(digest) for x in xrange(9)])


def _build_cb_url(url, user):
    return '%s?_cb=%s' % (url, _build_cache_buster(user))


def _get_new_user(old_user):
    for provider in PROVIDERS:
        if hasattr(old_user, provider):
            data = getattr(old_user, provider)
            try:
                identity = IdentityProvider.objects.get(
                    provider=provider,
                    external_user_id=data['external_user_id'],
                )
                new_user = identity.user
            except IdentityProvider.DoesNotExist:
                continue

            # Loop through again and assign properties
            for _provider in PROVIDERS:
                if hasattr(old_user, _provider):
                    setattr(new_user, _provider, getattr(old_user, _provider))
            return new_user
    return old_user


@never_cache
def logout(request, provider=None):
    redirect_url = '/'
    session_flush = True

    if 'next' in request.GET:
        redirect_url = request.GET['next']
        request.session['next'] = redirect_url
    elif 'next' in request.session:
        redirect_url = request.session['next']
        del request.session['next']

    if provider is not None and provider in PROVIDERS:
        user = request.session.get('user', None)
        if user is not None and hasattr(user, provider):
            delattr(user, provider)
            if any([hasattr(user, x) for x in PROVIDERS]):
                # Reset user if logged into other services.
                request.session['user'] = _get_new_user(user)
                request.session.modified = True  # Just to be sure
                session_flush = False

    if session_flush:
        request.session.flush()

    return redirect(redirect_url)


@never_cache
def status(request):
    user = request.session.get('user', None)
    obj = None
    if user and user.has_valid_session():
        identities = {}
        for provider in PROVIDERS:
            identities[provider] = getattr(user, provider, None)

        obj = {
            #'pk'        : user.id,
            'username'  : user.username,
            'image_url' : user.image_url,
            'created'   : user.created.strftime('%Y-%m-%d %H-%M-%S'),
            'banned'    : user.banned,
            'identities': identities,
        }

    return HttpResponse(json.dumps({'user': obj}), mimetype="application/json")


@never_cache
def submit(request):
    if request.POST:
        form = IdentityProviderForm(request)
        if form.is_valid():
            provider = form.cleaned_data['provider']
            user_info = {
                'token': form.cleaned_data['token'],
                'external_user_id': form.cleaned_data['external_user_id'],
                'name': form.cleaned_data['name'],
                'image_url': form.cleaned_data['image_url'],
                'data': form.cleaned_data['data'],
            }
            user = None

            if 'user' in request.session:
                user = request.session['user']
            request.session['user'] = \
                SocialUser.lookup(provider, user, user_info)
            return redirect('auth_status')

    return HttpResponse(
        json.dumps({'error': 'post request invalid'}),
        mimetype="application/json",
    )


def _get_access_token(request, provider):
    #if 'user' in request.session:
        #user = request.session.get('user')
        #identity = user.get_identity(provider)
        #if identity:
            #return json.loads(identity.token)
    
    if '%s_access_token' % provider in request.session:
        return request.session.get('%s_access_token' % provider)

    return (None, None)  # Compat with urlencode and twitter token


# Facebook

def call_facebook_api(request, method=None, **kwargs):
    graph_dict = {'access_token': _get_access_token(request, 'facebook')}
    graph_dict.update(kwargs)
    data = urllib.urlencode(graph_dict)
    url = 'https://graph.facebook.com/%s' % method
    if method == 'me': 
        url += '?%s' % data
        data = None
    try:
        url_call = urllib2.urlopen(url, data, URL_TIMEOUT).read()
    except urllib2.HTTPError, error:
        logging.error('HTTP Error!:')
        logging.error(error.read())
        url_call = "{}"
    response = json.loads(url_call)
    return response


@never_cache
def facebook(request):
    redirect_url = '/'
    if 'next' in request.GET:
        redirect_url = request.GET['next']
        request.session['next'] = redirect_url
    elif 'next' in request.session:
        redirect_url = request.session['next']
        del request.session['next']

    access_url = "https://graph.facebook.com/oauth/access_token"
    authorize_url = "https://graph.facebook.com/oauth/authorize"
    callback_url = request.build_absolute_uri()
    values = {
        'client_id': FACEBOOK_API_KEY,
        'redirect_uri': 'http://%s%s' % (request.get_host(), request.path),
        'scope': 'publish_stream',
    }
    
    if 'user' in request.session:
        user = request.session['user']
        identity = user.get_identity('facebook')
        if identity and not identity.is_expired():
            user.facebook = {
                'name': identity.name,
                'image_url': identity.image_url,
                'external_user_id': identity.external_user_id,
            }
            request.session['user'] = user
            request.session[TRACKER_NAME] = 'facebook'
            return redirect(_build_cb_url(redirect_url, user))
    
    # TODO: Add a way to manage error responses
    # error_reason=user_denied&error=access_denied&error_description=The+user+denied+your+request
    if 'error' in request.GET:
        logging.error('Error! %s: %s - %s' % (
            request.GET['error'],
            request.GET['error_reason'],
            ' '.join(request.GET['error_description'].split('+'))
        ))
        return redirect(redirect_url)

    if 'code' in request.GET:
        values['code'] = request.GET.get('code')
        values['client_secret'] = FACEBOOK_API_SECRET
        facebook_url = "%s?%s" % (access_url, urllib.urlencode(values))
        result = urllib2.urlopen(facebook_url, None, URL_TIMEOUT).read()
        access_token = re.findall('^access_token=([^&]*)', result)

        if len(access_token):
            access_token = access_token[0]
            expires = re.findall('.*?expires=(\d+)', result)
            expires = expires[0] if len(expires) else 9999
            request.session['facebook_access_token'] = access_token
            
            facebook_user = call_facebook_api(
                request,
                'me',
                **{'fields': 'id,name,picture'}
            )
            
            # Error handling
            if 'error' in facebook_user:
                logging.error('Error! %s: %s' % (
                    facebook_user['error']['type'],
                    facebook_user['error']['message'],
                ))
            else:
                user_info = {
                    'token': \
                        json.dumps(request.session['facebook_access_token']),
                    'external_user_id': facebook_user['id'],
                    'name': facebook_user['name'],
                    'image_url': facebook_user['picture'],
                    'expires': expires,
                    'data': facebook_user,
                }

                user = request.session.get('user', None)

                # Append to existing user object to allow login to multiple 
                # social services at once.

                # Call lookup first to update keys, etc.
                s_user = SocialUser.lookup('facebook', None, user_info)
                if user is not None:
                    s_user = user
                s_user.facebook = {
                    'name': user_info['name'],
                    'image_url': user_info['image_url'],
                    'external_user_id': user_info['external_user_id'],
                }
                request.session['user'] = s_user
                request.session[TRACKER_NAME] = 'facebook'
                redirect_url = _build_cb_url(redirect_url, s_user)
        return redirect(redirect_url) 

    redirect_url = "%s?%s" % (authorize_url, urllib.urlencode(values))
    return redirect(redirect_url)


# Twitter

def get_twitter_api(request):
    access_token = _get_access_token(request, 'twitter')
    auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
    auth.set_access_token(access_token[0], access_token[1])
    return tweepy.API(auth)


@never_cache
def twitter(request):
    redirect_url = '/'
    if 'next' in request.GET:
        redirect_url = request.GET['next']
        request.session['next'] = redirect_url
    elif 'next' in request.session:
        redirect_url = request.session['next']
        del request.session['next']

    if 'user' in request.session:
        user = request.session['user']
        identity = user.get_identity('twitter')
        if identity:
            user.twitter = {
                'name': identity.name,
                'image_url': identity.image_url,
                'external_user_id': identity.external_user_id,
            }
            request.session['user'] = user
            request.session[TRACKER_NAME] = 'twitter'
            return redirect(_build_cb_url(redirect_url, user))

    if 'oauth_verifier' in request.GET:
        auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
        token = request.session.get('twitter_request_token', None)

        if 'twitter_request_token' in request.session:
            del request.session['twitter_request_token']

        if token:
            auth.set_request_token(token[0], token[1])
            try:
                access_token = \
                    auth.get_access_token(request.GET.get('oauth_verifier'))
                # And now let's store it in the session!
                request.session['twitter_access_token'] = (
                    access_token.key,
                    access_token.secret,
                )
                
                twitter_user = get_twitter_api(request).me()
                user_info = {
                    'token': \
                        json.dumps(request.session['twitter_access_token']),
                    'external_user_id': twitter_user.id,
                    'name': twitter_user.screen_name,
                    'image_url': twitter_user.profile_image_url,
                    'data': twitter_user.__dict__,
                }
                
                user = request.session.get('user', None)

                # Append to existing user object to allow login to multiple 
                # social services at once.
                s_user = SocialUser.lookup('twitter', None, user_info)
                if user is not None:
                    s_user = user
                s_user.twitter = {
                    'name': user_info['name'],
                    'image_url': user_info['image_url'],
                    'external_user_id': user_info['external_user_id'],
                }
                request.session['user'] = s_user
                request.session[TRACKER_NAME] = 'twitter'
                redirect_url = _build_cb_url(redirect_url, s_user)

            except tweepy.TweepError, e:
                logging.error('Error! Failed to get twitter request token.')
                logging.error(e)
                
        return redirect(redirect_url) 

    # Authenticate with Twitter and get redirect_url
    callback_url = request.build_absolute_uri()
    auth = \
        tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET, callback_url)
    try:
        # Get redirect url
        redirect_url = auth.get_authorization_url()
        # Store the request token in the session
        request.session['twitter_request_token'] = \
            (auth.request_token.key, auth.request_token.secret)
    except tweepy.TweepError, e:
        logging.error('Error! Failed to get twitter request token.')
        logging.error(e)

    return redirect(redirect_url)


@never_cache
def google(request):
    redirect_url = '/'
    if 'next' in request.GET:
        redirect_url = request.GET['next']
        request.session['next'] = redirect_url
    elif 'next' in request.session:
        redirect_url = request.session['next']
        del request.session['next']

    if 'user' in request.session:
        user = request.session['user']
        identity = user.get_identity('google')
        if identity:
            user.google = {
                'name': identity.name,
                'image_url': identity.image_url,
                'external_user_id': identity.external_user_id,
            }
            request.session['user'] = user
            request.session[TRACKER_NAME] = 'google'
            return redirect(_build_cb_url(redirect_url, user))

    # Don't use build_absolute_uri so we can drop GET
    callback_url = '%s://%s%s' % (
        'https' if request.is_secure() else 'http',
        request.get_host(),
        request.path,
    )
    if 'error' in request.GET:
        logging.error('Error! %s: Reason %s - Description %s' % (
            request.GET['error'],
            request.GET.get('error_reason'),
            ' '.join(request.GET.get('error_description', '').split('+'))
        ))
        return redirect(redirect_url)
    elif 'code' in request.GET:
        try:
            o = oauth2.GooglePlus.create_from_authorization_code(
                request.GET['code'],
                GOOGLE_API_KEY,
                GOOGLE_API_SECRET,
                callback_url,
            )
            profile = o.get_user()
            user_info     = {
                'token': o.refresh_token and o.refresh_token or o.access_token,
                'external_user_id': profile['id'],
                'name': profile['displayName'],
                'image_url': profile['image']['url'],
                'expires': 3600,
                'data': profile,
            }

            user = request.session.get('user', None)

            # Append to existing user object to allow login to multiple 
            # social services at once.
            s_user = SocialUser.lookup('google', None, user_info)
            if user is not None:
                s_user = user
            s_user.google = {
                'name': user_info['name'],
                'image_url': user_info['image_url'],
                'external_user_id': user_info['external_user_id'],
            }
            request.session['user'] = s_user
            request.session[TRACKER_NAME] = 'google'
            redirect_url = _build_cb_url(redirect_url, s_user)
        except oauth2.RequestError, e:
            # 404 means user doesn't have google profile.
            # But the rest of this doesn't seem to have
            # any sort of error messages for users
            # so just passing for now
            if e.status == 404:
                pass
            logging.error(e)

        return redirect(redirect_url)

    # Authenticate with Google and get redirect_url
    redirect_url = oauth2.OAuth2Handler.get_auth_url(
        GOOGLE_API_KEY,
        GOOGLE_API_SECRET,
        callback_url,
        scopes=('https://www.googleapis.com/auth/plus.me',),
    )
    return redirect(redirect_url)


@never_cache
def test(request,u_id):
    redirect_url = '/'
    if 'next' in request.GET:
        redirect_url = request.GET['next']
        request.session['next'] = redirect_url
    elif 'next' in request.session:
        redirect_url = request.session['next']
        del request.session['next']

    # Get or Create a Social User with all identities
    if 'user' not in request.session:
        # The info is generic and used everywhere
        info = {
            'name': 'name %s' % u_id,
            'image_url': 'image_url_%s.jpg' % u_id,
            'external_user_id': u_id,
        }

        user, created = SocialUser.objects.get_or_create(username=info['name'])

        if created:
            for provider in PROVIDERS:
                identity = IdentityProvider(
                    user=user,
                    provider=provider, 
                    token=json.dumps(['%s-%s' % (provider, u_id)]),
                    external_user_id=info['external_user_id'],
                    name=info['name'],
                    image_url=info['image_url'],
                    expires=9999,
                    data={},
                )
                identity.save()
                setattr(user, provider, info)
        request.session['user'] = user

    return redirect(redirect_url)
