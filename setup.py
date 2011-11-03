from distutils.core import setup

setup(
	name         = 'red-social-auth',
	packages     = ['social_auth',],
	version      = 'v0.0.1.1',
	author       = 'RED Interactive Agency',
	author_email = 'geeks@ff0000.com',

	url          = 'http://www.github.com/ff0000/red-social-auth/',

	license      = 'MIT license',
	description  = """ A django app to add social authentication with Facebook Twitter and Google Plus""",

	long_description = open('README.markdown').read(),
	install_requires = ['tweepy',],

	classifiers  = (
		'Development Status :: 3 - Alpha',
		'Environment :: Web Environment',
		'Framework :: Django',
		'Intended Audience :: Developers',
		'License :: OSI Approved :: MIT License',
		'Programming Language :: Python',
	),
)
