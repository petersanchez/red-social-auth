import json, logging, re, urllib

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from social_auth.models import SocialUser, IdentityProvider

import tweepy

def logout(request):
	if 'user' in request.session: del request.session['user']
	return HttpResponseRedirect('/')

def _get_access_token(request, provider):
	if 'user' in request.session:
		user = request.session.get('user')
		identity = user.get_identity(provider)
		if identity:
			if provider == 'twitter':
				return json.loads(identity.token)
			return identity.token
	
	if '%s_access_token' % provider in request.session:
		return request.session.get('%s_access_token' % provider)
	
	return redirect(provider)

# Facebook
FACEBOOK_API_KEY    = getattr(settings,'FACEBOOK_API_KEY',None)
FACEBOOK_API_SECRET = getattr(settings,'FACEBOOK_API_SECRET',None)

def call_facebook_api(request, method=None, **kwargs):
	graph_dict = {'access_token' : _get_access_token(request, 'facebook')}
	graph_dict.update(kwargs)
	data = urllib.urlencode(graph_dict)
	url = 'https://graph.facebook.com/%s' % method

	if method !='me': 
		return json.loads(urllib.urlopen(url, data).read())
	else:
		url += '?%s' % data
		return json.loads(urllib.urlopen(url).read())

def facebook(request):
	access_url    = "https://graph.facebook.com/oauth/access_token"
	authorize_url = "https://graph.facebook.com/oauth/authorize"
	callback_url  = request.build_absolute_uri()
	values = {'client_id':    FACEBOOK_API_KEY,
              'redirect_uri': 'http://%s%s' % (request.get_host(), request.path),
              'scope':        'publish_stream'}
	
	if 'user' in request.session:
		user     = request.session['user']
		identity = user.get_identity('facebook')
		if identity: return HttpResponseRedirect('/')
    
	# TODO: Add a way to manage error responses
	# error_reason=user_denied&error=access_denied&error_description=The+user+denied+your+request
	if 'error' in request.GET:
		logging.warning(request, 'Could not authorize on Facebook!')
		return HttpResponseRedirect('/')

	if 'code' in request.GET:
		values['code']          = request.GET.get('code')
		values['client_secret'] = FACEBOOK_API_SECRET
		redirect_url = "%s?%s" % (access_url,urllib.urlencode(values))
		result       = urllib.urlopen(redirect_url).read() 
		access_token = re.findall('^access_token=([^&]*)', result)[0]
		request.session['facebook_access_token'] = access_token
		
		facebook_user = call_facebook_api(request, 'me', **{'fields':'id,name,picture'})
		user_info     = {
			'token'            : request.session['facebook_access_token'],
			'external_user_id' : facebook_user['id'],
			'name'             : facebook_user['name'],
			'image_url'        : facebook_user['picture'],
			'data'             : facebook_user,
			}

		user = None
		if 'user' in request.session:
			user = request.session['user']
		request.session['user'] = SocialUser.lookup('facebook', user, user_info)
		return HttpResponseRedirect('/') 
	redirect_url  = "%s?%s" % (authorize_url, urllib.urlencode(values))
	return HttpResponseRedirect(redirect_url)

# Twitter
TWITTER_API_KEY    = getattr(settings,'TWITTER_API_KEY',None)
TWITTER_API_SECRET = getattr(settings,'TWITTER_API_SECRET',None)

def get_twitter_api(request):
	access_token = _get_access_token(request,'twitter')
	auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
	auth.set_access_token(access_token[0], access_token[1])
	return tweepy.API(auth)

def twitter(request):

	if 'user' in request.session:
		user = request.session['user']
		identity = user.get_identity('twitter')
		if identity:
			return HttpResponseRedirect('/')

	if 'oauth_verifier' in request.GET:
		auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
		token = request.session.get('twitter_request_token')
		if 'twitter_request_token' in request.session:
			del request.session['twitter_request_token']
		auth.set_request_token(token[0], token[1])
		try:
			access_token = auth.get_access_token(request.GET.get('oauth_verifier'))
		except tweepy.TweepError:
			logging.warning('Error! Failed to get twitter request token.')
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
		request.session['user'] = SocialUser.lookup('twitter', user, user_info)

		return HttpResponseRedirect('/') 
	
	callback_url = request.build_absolute_uri()
	# Authenticate with Twitter and get redirect_url
	auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET, callback_url)
	try:
		redirect_url = auth.get_authorization_url()
	except tweepy.TweepError:
		logging.warning('Error! Failed to get twitter request token.')

	# Store the request token in the session
	request.session['twitter_request_token'] = (auth.request_token.key, auth.request_token.secret)
	return HttpResponseRedirect(redirect_url)

