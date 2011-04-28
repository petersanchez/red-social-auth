# RED Social Auth

This is a django app that adds Facebook and Twitter users to your project.

## Setup

1. The first step is to add your keys to the settings.py file:

        FACEBOOK_API_KEY    = 'yourapikey'
        FACEBOOK_API_SECRET = 'yourapisecret'
        TWITTER_API_KEY     = 'yourapikey'
        TWITTER_API_SECRET  = 'yourapisecret'

2. Next add 'social_auth' to your INSTALLED_APPS in your settings.py file.

3. Add the following line to your urls.py files:

        (r'&#94;auth/', include('social_auth.urls')),

4. Run 'python manage.py syncdb' on your project and you're done!


## Usage

This app is very easy to use.  Your login urls are:

    /auth/facebook/
    /auth/twitter/

The user will go to these urls, be directed through the oath protocol, and
will return to the home page.  To log out they need to visit:

    /auth/logout/


## Models

There are two models: SocialUser and IdentityProvider.  The first contains
a username and image_url for the user on your site.  The second model
stores the actual information from the provider, including the access
token that can be reused by other applications to connect with
Facebook or Twitter.


