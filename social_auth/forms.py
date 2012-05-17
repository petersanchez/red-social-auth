from django import forms
from social_auth.models import IdentityProvider


class IdentityProviderForm(forms.Form):
    """ A class to validate identity providers """

    class Meta:
        model = IdentityProvider
        exclude = ('user',)
