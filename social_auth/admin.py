from django.contrib import admin
from social_auth.models import SocialUser, IdentityProvider

class IdentityProviderInline(admin.TabularInline):
	model = IdentityProvider
	extra = 0

class SocialUserAdmin(admin.ModelAdmin): 
	list_display  = ('username', 'image_url', 'created')
	search_fields = ['username',]
	list_filter   = ['created',]
	inlines = [IdentityProviderInline,]

admin.site.register(SocialUser,SocialUserAdmin)
