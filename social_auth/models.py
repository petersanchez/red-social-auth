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
	created   = models.DateTimeField(auto_now_add=True, db_index=True)
	def __unicode__(self):
		return self.username

	def get_identity(self, provider):
			identity = self.identityprovider_set.filter(provider=provider)[:1]
			return identity and identity[0] or None

	@staticmethod
	def lookup(provider, user, info):
		""" A method to get or create an identity provider for a user """

		try:
			identity = IdentityProvider.objects.get(provider = provider,
												external_user_id = info['external_user_id'])
			user = identity.user
			if not user.username:
				user.username = info['name']
				user.save()
			if not user.image_url:
				user.image_url = info['image_url']
				user.save()

		except IdentityProvider.DoesNotExist:
			identity = IdentityProvider(
							provider         = provider, 
							token            = info['token'],
							external_user_id = info['external_user_id'],
							name             = info['name'],
							image_url        = info['image_url'],
							data             = info['data']
							)
			identity.save()
			if not user:
				user = SocialUser(
						username  = identity.name,
						image_url = identity.image_url)
				user.save()
			identity.user = user
			identity.save()
		return user

