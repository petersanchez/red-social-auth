from django.conf.urls.defaults import *
from django.conf import settings

urlpatterns = patterns('social_auth.views',
	url(r'^facebook/$', 'facebook', name='auth_facebook'),
	url(r'^twitter/$',  'twitter',  name='auth_twitter'),
	url(r'^logout/$',   'logout',   name='auth_logout'),
	url(r'^status/$',   'status',   name='auth_status'), 
	url(r'^submit/$',   'submit',   name='auth_submit'), 
)

