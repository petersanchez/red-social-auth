from django.db import models

PROVIDER_CHOICES = (
	('facebook','facebook'),
	('twitter', 'twitter'),
)

class IdentityProvider(models.Model):
	user         = models.ForeignKey('social_auth.SocialUser',blank=True,null=True)
	
	provider     = models.CharField(max_length=10,choices=PROVIDER_CHOICES)
	token_key    = models.CharField(max_length=200)
	token_secret = models.CharField(max_length=200)
	
	pic          = models.CharField(max_length=200,blank=True)
	name         = models.CharField(max_length=200,blank=True)
	data         = models.TextField(max_length=200,blank=True)
	
	def __unicode__(self):
		return '%s - %s' % (self.user,self.provider)

class SocialUser(models.Model):
	username = models.CharField(max_length=200)

	def __unicode__(self):
		return self.username

	def get_identity(self,provider):
		for identity in self.identityprovider_set.all():
			if identity.provider == provider: return identity

	@property
	def name(self):
		for identity in self.identityprovider_set.all():
			if identity.name: return identity.name
	
	@property
	def pic(self):
		for identity in self.identityprovider_set.all():
			if identity.pic: return identity.pic

	@staticmethod
	def lookup(provider,info):
		""" A method to get or create an identity provider for a user """

		identity,created = IdentityProvider.objects.get_or_create(
						provider     = provider,
						token_key    = info['token_key'],
						token_secret = info['token_secret'],
						defaults=info)

		if created:
			user = SocialUser(username=identity.name)
			user.save()
			identity.user = user
			identity.save()
		else:
			identity.name = info['name']
			identity.pic  = info['pic']
			identity.data = info['data']
			user = identity.user
			if not user.username:
				user.username = identity.name
				user.save()
		
		return user

