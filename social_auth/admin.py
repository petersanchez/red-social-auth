from django.conf import settings
from django.contrib import admin
from social_auth.models import SocialUser, IdentityProvider

def user_image(obj):
	return ('<img src="%s" width="80" />' % (obj.image_url))
user_image.short_description = 'User Image'
user_image.allow_tags = True

class IdentityProviderInline(admin.TabularInline):
	model = IdentityProvider
	fields  = ('provider', 'name', 'external_user_id', 'token', 'expires')
	extra = 0

class SocialUserAdmin(admin.ModelAdmin): 
	list_display  = ('username', user_image, 'banned', 'created')
	search_fields = ['username',]
	list_filter   = ['created','banned']
	inlines = [IdentityProviderInline,]

admin.site.register(SocialUser,SocialUserAdmin)
