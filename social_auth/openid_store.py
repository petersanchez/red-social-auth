"""
An openid store for the social_auth schema, somewhat borrowed from 
http://stackoverflow.com/questions/4307677/django-google-federated-login
"""

import time, base64

from django.db import models
from django.conf import settings
from django.utils.hashcompat import md5_constructor

from openid.store import nonce, interface
from openid.association import Association

from social_auth.models import Openid_Association, Openid_Nonce

class SocialAuthStore(interface.OpenIDStore):

	def storeAssociation(self, server_url, association):
		assoc = Openid_Association(
		        server_url = server_url,
		        handle = association.handle,
		        secret = base64.encodestring(association.secret),
		        issued = association.issued,
		        lifetime = association.lifetime,
		        assoc_type = association.assoc_type
		)
		assoc.save()

	def getAssociation(self, server_url, handle=None):
		assocs = []
		if handle is not None:
			assocs = Openid_Association.objects.filter(
			        server_url = server_url, handle = handle
			)
		else:
			assocs = Openid_Association.objects.filter(
			        server_url = server_url
			)
		if not assocs:
			return None
		associations = []
		for assoc in assocs:
			association = Association(
			        assoc.handle, base64.decodestring(assoc.secret), assoc.issued,
			        assoc.lifetime, assoc.assoc_type
			)
			if association.getExpiresIn() == 0:
				self.removeAssociation(server_url, assoc.handle)
			else:
				associations.append((association.issued, association))
		if not associations:
			return None
		return associations[-1][1]

	def removeAssociation(self, server_url, handle):
		assocs = list(Association.objects.filter(
		        server_url = server_url, handle = handle
		))
		assocs_exist = len(assocs) > 0
		for assoc in assocs:
			assoc.delete()
		return assocs_exist

	def useNonce(self, server_url, timestamp, salt):
		# Has nonce expired?
		if abs(timestamp - time.time()) > nonce.SKEW:
			return False
		try:
			openid_nonce = Openid_Nonce.objects.get(
			        server_url__exact = server_url,
			        timestamp__exact = timestamp,
			        salt__exact = salt
			)
		except Openid_Nonce.DoesNotExist:
			openid_nonce = Openid_Nonce.objects.create(
			        server_url = server_url,
			        timestamp = timestamp,
			        salt = salt
			)
			return True
		openid_nonce.delete()
		return False

	def cleanupNonce(self):
		Openid_Nonce.objects.filter(
		        timestamp__lt = (int(time.time()) - nonce.SKEW)
		        ).delete()

	def cleaupAssociations(self):
		Openid_Association.objects.extra(
		        where=['issued + lifetimeint < (%s)' % time.time()]
		        ).delete()

	def getAuthKey(self):
		# Use first AUTH_KEY_LEN characters of md5 hash of SECRET_KEY
		return md5_constructor.new(settings.SECRET_KEY).hexdigest()[:self.AUTH_KEY_LEN]

	def isDumb(self):
		return False