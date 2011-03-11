import logging

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import redirect

import tweepy

from social_auth.models import SocialUser,IdentityProvider

def logout(request):
	if 'user' in request.session:
		del request.session['user']
	return HttpResponseRedirect('/')

def _get_access_token(request,provider):
	access_token = (None,None)
	if 'user' in request.session:
		user = request.session.get('user')
		identity = user.get_identity(provider)
		access_token = (identity.token_key,identity_token_secret)
	elif '%s_access_token' % provider in request.session:
		access_token = request.session.get('%s_access_token'%provider)
	else:
		return redirect(provider)
	return access_token

# Facebook

FACEBOOK_API_KEY    = getattr(settings,'FACEBOOK_API_KEY',None)
FACEBOOK_API_SECRET = getattr(settings,'FACEBOOK_API_SECRET',None)

def get_facebook_api(request):
	access_token = _get_access_token(request,'facebook')

	#TODO: Need to actually build out api and return it here, see twitter
	api = None
	return api 

def facebook(request):
	pass

# Twitter

TWITTER_API_KEY    = getattr(settings,'TWITTER_API_KEY',None)
TWITTER_API_SECRET = getattr(settings,'TWITTER_API_SECRET',None)

def get_twitter_api(request):
	access_token = _get_access_token(request,'twitter')
	auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
	auth.set_access_token(access_token[0], access_token[1])
	api = tweepy.API(auth)
	return api

def twitter(request):

	if 'user' in request.session:
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
			'token_key'    : access_token.key,
			'token_secret' : access_token.secret,
			'name'         : twitter_user.screen_name,
			'pic'          : twitter_user.profile_image_url,
			'data'         : twitter_user.__dict__,
			}
		request.session['user'] = SocialUser.lookup('twitter',user_info)

		return HttpResponseRedirect('/') 
	
	# Set callback url
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

