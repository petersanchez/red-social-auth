import datetime
from django.conf import settings
from django.db import models

PROVIDERS = getattr(
    settings,
    'SOCIAL_AUTH_PROVIDERS',
    ('facebook', 'twitter', 'google'),
)
PROVIDER_CHOICES = [(x,x) for x in PROVIDERS]


class IdentityProvider(models.Model):
    user = models.ForeignKey('social_auth.SocialUser')
    provider = models.CharField(max_length=10, choices=PROVIDER_CHOICES)
    token = models.CharField(max_length=200, blank=True)
    external_user_id = models.CharField(max_length=200, blank=True)
    name = models.CharField(max_length=200, blank=True)
    image_url = models.CharField(max_length=200, blank=True)
    expires = models.IntegerField(blank=True, null=True)
    data = models.TextField(max_length=200, blank=True)
    modified = models.DateTimeField(auto_now=True, db_index=True)

    def __unicode__(self):
        return '%s - %s' % (self.user, self.provider)

    def is_expired(self):
        if self.provider == 'twitter':
            return False
        return self.modified + \
            datetime.timedelta(seconds=self.expires) < datetime.datetime.now()


class SocialUser(models.Model):
    username = models.CharField(max_length=200)
    image_url = models.CharField(max_length=200)
    banned = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True, db_index=True)

    def __unicode__(self):
        return self.username

    @property
    def info(self):
        ''' Return the first identity based on the PROVIDERS tuple.
            Order is important. The first match is returned.

            The "identity" is assigned at the time of login via the 
            individual provider views. ie, user.twitter or user.facebook.
        '''
        for provider in PROVIDERS:
            if hasattr(self, provider);
                return getattr(self, provider)
        return None

    def get_identity(self, provider):
        try:
            return self.identityprovider_set.filter(provider=provider)[0]
        except IndexError:
            return None

    def has_valid_session(self):
        for identity in self.identityprovider_set.all():
            if identity.provider == 'twitter':
                continue
            else:
                return (not identity.is_expired())
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
                provider=provider,
                external_user_id=info['external_user_id'],
            )
            identity.expires = expires
            identity.token = info['token']
            identity.save()
            user = identity.user
            user_needs_save = False

            if not user.username:
                user.username = info['name']
                user_needs_save = True
            if not user.image_url:
                user.image_url = info['image_url']
                user_needs_save = True

            if user_needs_save:
                user.save()
        except IdentityProvider.DoesNotExist:  # MultipleObjectsReturned ?
            if not user:
                user = SocialUser(
                    username=info['name'],
                    image_url=info['image_url'],
                )
                user.save()

            identity = IdentityProvider(
                user=user,
                provider=provider, 
                token=info['token'],
                external_user_id=info['external_user_id'],
                name=info['name'],
                image_url=info['image_url'],
                expires=expires,
                data=info['data'],
            )
            identity.save()
        return user
