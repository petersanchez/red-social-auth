from django.contrib import admin

from social_auth.models import SocialUser, IdentityProvider

class SocialUserAdmin(admin.ModelAdmin): 
	list_display = ('username','image_url',)
admin.site.register(SocialUser,SocialUserAdmin)

class IdentityProviderAdmin(admin.ModelAdmin):
	list_display = ('user','provider','name','image_url',)
	list_filter  = ('provider',)
admin.site.register(IdentityProvider,IdentityProviderAdmin)
