from django.db import models

PROVIDER_CHOICES = (
	('facebook','facebook'),
	('twitter', 'twitter'),
)

class IdentityProvider(models.Model):
	user             = models.ForeignKey('social_auth.SocialUser', blank=True, null=True)
	provider         = models.CharField(max_length=10,choices=PROVIDER_CHOICES)
	token            = models.CharField(max_length=200)
	external_user_id = models.CharField(max_length=200,blank=True)
	name             = models.CharField(max_length=200,blank=True)
	image_url        = models.CharField(max_length=200,blank=True)
	data             = models.TextField(max_length=200,blank=True)
	
	def __unicode__(self):
		return '%s - %s' % (self.user,self.provider)

class SocialUser(models.Model):
	username  = models.CharField(max_length=200)
	image_url = models.CharField(max_length=200)

	def __unicode__(self):
		return self.username

	def get_identity(self, provider):
		try: 
			return self.identityprovider_set.filter(provider=provider)[0]
		except: 
			return None

	@staticmethod
	def lookup(provider,user,info):
		""" A method to get or create an identity provider for a user """

		identity,created = IdentityProvider.objects.get_or_create(
						provider = provider,
						token    = info['token'],
						defaults=info)

		if created:
			if not user:
				user = SocialUser(
						username  = identity.name,
						image_url = identity.image_url)
				user.save()
			identity.user = user
			identity.save()
		else:
			identity.name       = info['name']
			identity.image_url  = info['image_url']
			identity.data       = info['data']
			user = identity.user
			if not user.username:
				user.username = identity.name
				user.save()
			if not user.image_url:
				user.image_url = identity.image_url
				user.save()
		
		return user

