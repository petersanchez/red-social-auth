import json, logging, re, urllib, urllib2

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt

import tweepy
from social_auth import oauth2
from social_auth import https_connection
from social_auth.forms  import IdentityProviderForm,PreAuthedForm
from social_auth.models import SocialUser, IdentityProvider, PROVIDERS
from social_auth.oauth2 import VerifiedHTTPSConnection

URL_TIMEOUT         = getattr(settings, 'SOCIAL_AUTH_URL_TIMEOUT', 15)
FACEBOOK_API_KEY    = getattr(settings, 'FACEBOOK_API_KEY', None)
FACEBOOK_API_SECRET = getattr(settings, 'FACEBOOK_API_SECRET', None)
TWITTER_API_KEY     = getattr(settings, 'TWITTER_API_KEY', None)
TWITTER_API_SECRET  = getattr(settings, 'TWITTER_API_SECRET', None)
GOOGLE_API_SECRET = getattr(settings, 'GOOGLE_API_SECRET', None)
GOOGLE_API_KEY = getattr(settings, 'GOOGLE_API_KEY', None)

@never_cache
def logout(request):
	redirect_url = '/'
	if 'next' in request.GET:
		redirect_url = request.GET['next']
		request.session['next'] = redirect_url
	elif 'next' in request.session:
		redirect_url = request.session['next']
		del request.session['next']

	request.session.flush()
	return HttpResponseRedirect(redirect_url)

@never_cache
def status(request):
	user = request.session.get('user',None)
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

	return HttpResponse(json.dumps({'user':obj}),mimetype="application/json")

@never_cache
def submit(request):
	if request.POST:
		form = IdentityProviderForm(request)
		if form.is_valid():
			provider = form.cleaned_data['provider']
			user_info     = {
				'token'            : form.cleaned_data['token'],
				'external_user_id' : form.cleaned_data['external_user_id'],
				'name'             : form.cleaned_data['name'],
				'image_url'        : form.cleaned_data['image_url'],
				'data'             : form.cleaned_data['data'],
				}
			user = None
			if 'user' in request.session:
				user = request.session['user']
			request.session['user'] = SocialUser.lookup(provider, user, user_info)
			return redirect('auth_status')

	return HttpResponse(json.dumps({'error':'post request invalid'}),mimetype="application/json")
	
	
def pre_authed(request):
	"""This strikes me as totally insecure"""
	
	jsonr = json.dumps({'error':'invalid request'})
	provider = None
	token = None
	
	if request.REQUEST.has_key('provider'):
		form = PreAuthedForm(request.REQUEST)
		
		if form.is_valid():
			
			provider = form.cleaned_data['provider']
			token = form.cleaned_data['token']
			
			# twitter gives us and id and a secret so we have to format it's 
			# token for our usage
			if form.cleaned_data['provider'] == 'twitter':
				token =  form.cleaned_data['token'].split(",")
			
			s_user = SocialUser.create_from_token(provider,token)
			print "hello"
			print s_user
			request.session['user'] = s_user
			identity = s_user.identityprovider_set.get(provider=provider).__dict__
			
			# ya it's ugly
			del(identity['data'])
			del(identity['modified'])
			del(identity['user_id'])
			del(identity['_state'])
			del(identity['token'])
			
			# Bad but we are in a hurry
			identity['cookie'] = request.COOKIES[settings.SESSION_COOKIE_NAME] 
			jsonr = json.dumps(identity)
			
		else:
			jsonr = json.dumps(form.errors)
	
	
	return HttpResponse(jsonr,mimetype="application/json")
		
		
		


@never_cache
@csrf_exempt
def pre_authed(request):
	"""This strikes me as totally insecure"""
	
	jsonr = json.dumps({'error':'invalid request'})
	provider = None
	token = None
	
	if request.REQUEST.has_key('provider'):
		form = PreAuthedForm(request.REQUEST)
		
		if form.is_valid():
			
			provider = form.cleaned_data['provider']
			token = form.cleaned_data['token']
			
			# twitter gives us and id and a secret so we have to format it's 
			# token for our usage
			if form.cleaned_data['provider'] == 'twitter':
				token =  form.cleaned_data['token'].split(",")
			
			s_user = SocialUser.create_from_token(provider,token)
			
			request.session['user'] = s_user
			identity = s_user.identityprovider_set.get(provider=provider).__dict__
			
			# ya it's ugly
			del(identity['data'])
			del(identity['modified'])
			del(identity['user_id'])
			del(identity['_state'])
			del(identity['token'])
			
			# Bad but we are in a hurry
			jsonr = json.dumps(identity)
			
		else:
			jsonr = json.dumps(form.errors)
	
	
	return HttpResponse(jsonr,mimetype="application/json")
		
		
		

def _get_access_token(request, provider):
	if 'user' in request.session:
		user = request.session.get('user')
		identity = user.get_identity(provider)
		if identity:
			return json.loads(identity.token)
	
	if '%s_access_token' % provider in request.session:
		return request.session.get('%s_access_token' % provider)
	
	return redirect('auth_%s' % provider)

# Facebook

def call_facebook_api(request, method=None, **kwargs):
	graph_dict = {'access_token' : _get_access_token(request, 'facebook')}
	graph_dict.update(kwargs)
	data = urllib.urlencode(graph_dict)
	url  = 'https://graph.facebook.com/%s' % method
	if method =='me': 
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

	access_url    = "https://graph.facebook.com/oauth/access_token"
	authorize_url = "https://graph.facebook.com/oauth/authorize"
	callback_url  = request.build_absolute_uri()
	values        = {
		'client_id'    : FACEBOOK_API_KEY,
  		'redirect_uri' : 'http://%s%s' % (request.get_host(), request.path),
		'scope'        : 'publish_stream'
		}
	
	if 'user' in request.session:
		user     = request.session['user']
		identity = user.get_identity('facebook')
		if identity and not identity.is_expired():
			user.facebook = {
				'name'             : identity.name,
				'image_url'        : identity.image_url,
				'external_user_id' : identity.external_user_id,
				}
			request.session['user'] = user
			return HttpResponseRedirect(redirect_url)
    
	# TODO: Add a way to manage error responses
	# error_reason=user_denied&error=access_denied&error_description=The+user+denied+your+request
	if 'error' in request.GET:
		logging.error('Error! %s: %s - %s' % (
			request.GET['error'],
			request.GET['error_reason'],
			' '.join(request.GET['error_description'].split('+')))
			)
		return HttpResponseRedirect(redirect_url)

	if 'code' in request.GET:
		values['code']          = request.GET.get('code')
		values['client_secret'] = FACEBOOK_API_SECRET
		facebook_url = "%s?%s" % (access_url, urllib.urlencode(values))
		result       = urllib2.urlopen(facebook_url, None, URL_TIMEOUT).read()
		access_token = re.findall('^access_token=([^&]*)', result)
		if len(access_token):
			access_token = access_token[0]
			expires      = re.findall('.*?expires=(\d+)', result)
			if len(expires): expires = expires[0]
			else: expires = 9999
			request.session['facebook_access_token'] = access_token
			
			facebook_user = call_facebook_api(request, 'me', **{'fields':'id,name,picture'})
			
			# Error handling
			if 'error' in facebook_user:
				logging.error('Error! %s: %s' % (
					facebook_user['error']['type'],
					facebook_user['error']['message'],
					))
			else:
				user_info     = {
					'token'            : json.dumps(request.session['facebook_access_token']),
					'external_user_id' : facebook_user['id'],
					'name'             : facebook_user['name'],
					'image_url'        : facebook_user['picture'],
					'expires'          : expires,
					'data'             : facebook_user,
				}

				user = request.session.get('user',None)
				s_user = SocialUser.lookup('facebook', user, user_info)
				s_user.facebook = {
					'name'             : user_info['name'],
					'image_url'        : user_info['image_url'],
					'external_user_id' : user_info['external_user_id'],
				}
				request.session['user'] = s_user
		return HttpResponseRedirect(redirect_url) 
	redirect_url  = "%s?%s" % (authorize_url, urllib.urlencode(values))
	return HttpResponseRedirect(redirect_url)

# Twitter

def get_twitter_api(request):
	access_token = _get_access_token(request,'twitter')
	auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
	auth.set_access_token(access_token[0], access_token[1])
	return tweepy.API(auth).me()

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
				'name'             : identity.name,
				'image_url'        : identity.image_url,
				'external_user_id' : identity.external_user_id,
				}
			request.session['user'] = user
			return HttpResponseRedirect(redirect_url)

	if 'oauth_verifier' in request.GET:
		auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
		token = request.session.get('twitter_request_token',None)
		if 'twitter_request_token' in request.session:
			del request.session['twitter_request_token']
		if token:
			auth.set_request_token(token[0], token[1])
			try:
				access_token = auth.get_access_token(request.GET.get('oauth_verifier'))
				# And now let's store it in the session!
				request.session['twitter_access_token'] = (access_token.key, access_token.secret)
				
				twitter_user = get_twitter_api(request).me()
				user_info = {
					'token'            : json.dumps(request.session['twitter_access_token']),
					'external_user_id' : twitter_user.id,
					'name'             : twitter_user.screen_name,
					'image_url'        : twitter_user.profile_image_url,
					'data'             : twitter_user.__dict__,
				}
				
				user = None
				if 'user' in request.session:
					user = request.session['user']
				s_user = SocialUser.lookup('twitter', user, user_info)
				s_user.twitter = {
							'name'             : user_info['name'],
							'image_url'        : user_info['image_url'],
							'external_user_id' : user_info['external_user_id'],
						}
				request.session['user'] = s_user

			except tweepy.TweepError, e:
				logging.error('Error! Failed to get twitter request token.')
				logging.error(e)
				
		return HttpResponseRedirect(redirect_url) 

	# Authenticate with Twitter and get redirect_url
	callback_url = request.build_absolute_uri()
	auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET, callback_url)
	try:
		# Get redirect url
		redirect_url = auth.get_authorization_url()
		# Store the request token in the session
		request.session['twitter_request_token'] = (auth.request_token.key, auth.request_token.secret)
	except tweepy.TweepError, e:
		logging.error('Error! Failed to get twitter request token.')
		logging.error(e)

	return HttpResponseRedirect(redirect_url)

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
				'name'             : identity.name,
				'image_url'        : identity.image_url,
				'external_user_id' : identity.external_user_id,
				}
			request.session['user'] = user
			return HttpResponseRedirect(redirect_url)

	# Don't use build_absolute_uri so we can drop GET
	callback_url = '%s://%s%s' % (request.is_secure() and 'https' or 'http',
	                             request.get_host(), request.path)
	if 'error' in request.GET:
		logging.error('Error! %s: Reason %s - Description %s' % (
			request.GET['error'],
			request.GET.get('error_reason'),
			' '.join(request.GET.get('error_description', '').split('+')))
			)
		return HttpResponseRedirect(redirect_url)
	elif 'code' in request.GET:
		try:
			o = oauth2.GooglePlus.create_from_authorization_code(
			                       request.GET['code'], GOOGLE_API_KEY,
			                       GOOGLE_API_SECRET, callback_url,)
			profile = o.get_user()
			user_info     = {
				'token'            : o.refresh_token and o.refresh_token or o.access_token,
				'external_user_id' : profile['id'],
				'name'             : profile['displayName'],
				'image_url'        : profile['image']['url'],
				'expires'          : 3600,
				'data'             : profile,
				}

			user = request.session.get('user',None)
			s_user = SocialUser.lookup('google', user, user_info)
			s_user.google = {
						'name'             : user_info['name'],
						'image_url'        : user_info['image_url'],
						'external_user_id' : user_info['external_user_id'],
					}
			request.session['user'] = s_user
		except oauth2.RequestError, e:
			# 404 means user doesn't have google profile.
			# But the rest of this doesn't seem to have
			# any sort of error messages for users
			# so just passing for now
			if e.status == 404:
				pass
			logging.error(e)

		return HttpResponseRedirect(redirect_url)

	# Authenticate with Google and get redirect_url
	redirect_url = oauth2.OAuth2Handler.get_auth_url(GOOGLE_API_KEY,
	                          GOOGLE_API_SECRET, callback_url,
                              scopes=('https://www.googleapis.com/auth/plus.me',) )

	return HttpResponseRedirect(redirect_url)

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
			'name'            : 'name %s' % u_id,
			'image_url'       : 'image_url_%s.jpg' % u_id,
			'external_user_id': u_id,
		}

		user,created = SocialUser.objects.get_or_create(username=info['name'])

		if created:
			for provider in PROVIDERS:
				identity = IdentityProvider(
					user             = user,
					provider         = provider, 
					token            = json.dumps(['%s-%s' % (provider,u_id)]),
					external_user_id = info['external_user_id'],
					name             = info['name'],
					image_url        = info['image_url'],
					expires          = 9999,
					data             = {},
				)
				identity.save()
				setattr(user, provider, info)
		request.session['user'] = user

	return HttpResponseRedirect(redirect_url)

