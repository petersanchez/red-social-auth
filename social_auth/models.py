import logging
import datetime
import tweepy
import json
import urllib, urllib2
from social_auth import oauth2

from django.conf import settings
from django.db import models



PROVIDERS = getattr(settings, 'SOCIAL_AUTH_PROVIDERS', ('facebook', 'twitter', 'google'))
PROVIDER_CHOICES = [(x,x) for x in PROVIDERS]
URL_TIMEOUT         = getattr(settings, 'SOCIAL_AUTH_URL_TIMEOUT', 15)

class IdentityProvider(models.Model):
	user             = models.ForeignKey('social_auth.SocialUser')
	provider         = models.CharField(max_length=10,choices=PROVIDER_CHOICES)
	token            = models.CharField(max_length=200,blank=True)
	external_user_id = models.CharField(max_length=200,blank=True)
	name             = models.CharField(max_length=200,blank=True)
	image_url        = models.CharField(max_length=200,blank=True)
	expires          = models.IntegerField(blank=True, null=True)
	data             = models.TextField(max_length=200,blank=True)
	modified         = models.DateTimeField(auto_now=True, db_index=True)
	def __unicode__(self):
		return '%s - %s' % (self.user,self.provider)
	def is_expired(self):
		if self.provider == 'twitter': return False
		return self.modified + datetime.timedelta(seconds=self.expires) < datetime.datetime.now()

class SocialUser(models.Model):
	username  = models.CharField(max_length=200)
	image_url = models.CharField(max_length=200)
	banned    = models.BooleanField(default=False)
	created   = models.DateTimeField(auto_now_add=True, db_index=True)
	def __unicode__(self):
		return self.username
	
	@staticmethod
	def create_from_token(provider,token):
		""" 
		Pass me a provider and the access token and I'll set up a 
		SocialUser and IdentityProvider
		"""
		s_user = None
		if provider == 'twitter':
			auth = tweepy.OAuthHandler(settings.TWITTER_API_KEY, settings.TWITTER_API_SECRET)
			auth.set_access_token(token[0], token[1])
			twitter_user = tweepy.API(auth).me()
			user_info = {
				'token'            : json.dumps(token),
				'external_user_id' : twitter_user.id,
				'name'             : twitter_user.screen_name,
				'image_url'        : twitter_user.profile_image_url,
				'data'             : twitter_user.__dict__,
			}
			s_user = SocialUser.lookup('twitter', None, user_info)
		elif provider == 'facebook':
			
			graph_dict = {
				'access_token' : token,
				'fields':'id,name,picture'
			}
			
			data = urllib.urlencode(graph_dict)
			url  = 'https://graph.facebook.com/me?%s' % data
			
			try:
				url_call = urllib2.urlopen(url, None, URL_TIMEOUT).read()
			except urllib2.HTTPError, error:
				logging.error('HTTP Error!:')
				logging.error(error.read())
				url_call = "{}"
			
			facebook_user = json.loads(url_call) 
			
			
			user_info = {
				'token'            : token,
				'external_user_id' : facebook_user['id'],
				'name'             : facebook_user['name'],
				'image_url'        : facebook_user['picture'],
				'data'             : url_call
			}

			s_user = SocialUser.lookup('facebook', None, user_info)
			
		elif provider == 'google':

			o = oauth2.GooglePlus(token, settings.GOOGLE_API_KEY,
			                       settings.GOOGLE_API_SECRET)
			
			profile = o.get_user()
			user_info     = {
				'token'            : o.refresh_token,
				'external_user_id' : profile['id'],
				'name'             : profile['displayName'],
				'image_url'        : profile['image']['url'],
				'expires'          : 3600,
				'data'             : profile,
				}
			s_user = SocialUser.lookup('google', None, user_info)
			
		return s_user

	def get_identity(self, provider):
		identity = self.identityprovider_set.filter(provider=provider)[:1]
		return identity and identity[0] or None

	def has_valid_session(self):
		for identity in self.identityprovider_set.all():
			if identity.provider == 'twitter': continue
			else: return not identity.is_expired()
		return True

	@staticmethod
	def is_banned(user):
		user = SocialUser.objects.get(id=user.id)
		return user.banned

	@staticmethod
	def lookup(provider, user, info):
		""" A method to get or create an identity provider for a user """
		
		expires = info.get('expires', 0)
		try:
			identity = IdentityProvider.objects.get(
							provider = provider,
							external_user_id = info['external_user_id'])
							
			identity.expires = expires
			identity.token   = info['token']
			identity.save()
			
			user = identity.user
			
			if not user.username:
				user.username = info['name']
				user.save()
			if not user.image_url:
				user.image_url = info['image_url']
				user.save()

		except:
			if not user:
				user = SocialUser(
						username  = info['name'],
						image_url = info['image_url'])
				user.save()
			identity = IdentityProvider(
							user             = user,
							provider         = provider, 
							token            = info['token'],
							external_user_id = info['external_user_id'],
							name             = info['name'],
							image_url        = info['image_url'],
							expires          = expires,
							data             = info['data']
							)
			identity.save()
		return user

