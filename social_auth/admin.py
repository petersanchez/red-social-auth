from django.contrib import admin

from social_auth.models import SocialUser, IdentityProvider

class SocialUserAdmin(admin.ModelAdmin): pass
admin.site.register(SocialUser,SocialUserAdmin)

class IdentityProviderAdmin(admin.ModelAdmin): pass
admin.site.register(IdentityProvider,IdentityProviderAdmin)
