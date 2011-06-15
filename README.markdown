# RED Social Auth

This is a django app that adds Facebook and Twitter users to your project.

Maintainer: Chris Gilmer at FF0000

## Setup

1. The first step is to add your keys to the settings.py file:

        FACEBOOK_API_KEY    = 'yourapikey'
        FACEBOOK_API_SECRET = 'yourapisecret'
        TWITTER_API_KEY     = 'yourapikey'
        TWITTER_API_SECRET  = 'yourapisecret'

2. You may additionally add the following settings:

        SOCIAL_AUTH_URL_TIMEOUT = 15    # Defaults to 15 seconds
        SOCIAL_AUTH_DEBUG       = False # Defaults to False

3. Next add 'social_auth' to your INSTALLED_APPS in your settings.py file.

4. Add the following line to your urls.py files:

        (r'^auth/', include('social_auth.urls')),

5. Run 'python manage.py syncdb' on your project and you're done!


## Usage

This app is very easy to use.  Your login urls are:

    /auth/facebook/
    /auth/twitter/

The user will go to these urls, be directed through the oath protocol, and
will return to the home page.  To log out they need to visit:

    /auth/logout/

If for some reason you need to have an additional login method to either
Facebook or Twitter on your site you can still use red-social-auth to 
log in.  An example of this might be if you have flash or some native
app on your website that obfuscates the redirect but still returns the 
access token.  The trick is to post the identity provider information to the
following url:

    /auth/submit/

It is required that you post both the 'provider' (ie 'twitter' or 'facebook')
and the access 'token' here.  Additionally you can post the 'external_user_id',
'name', 'image_url', and any 'data' (as long as it's in json format).  When
the post is successful it will either find and login the user or create a new
user with the identity provider information.

If you wish to test without having to authenticate to either services then you'll
want to enable the setting:

    SOCIAL_AUTH_DEBUG = True # Defaults to False

With this enabled you can log in a user in the following way:

    /auth/test/<u_id>

Here <u_id> is any positive integer and will be used to create a fake user that
is authenticated with both Facebook and Twitter.  Calls to the respective api's
will not work but for testing you may simply want to hit /auth/status/ to get
information.  You can also design a system that will use the post logic to each
of the services using this user and in conjunction with the SOCIAL_AUTH_DEBUG 
setting will not actually post.  This was designed primarily for load testing.

## Models

There are two models: SocialUser and IdentityProvider.  The first contains
a username and image_url for the user on your site.  The second model
stores the actual information from the provider, including the access
token that can be reused by other applications to connect with
Facebook or Twitter and the expiry information for Facebook.

