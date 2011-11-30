from django import forms

from social_auth.models import IdentityProvider,PROVIDER_CHOICES

class IdentityProviderForm(forms.ModelForm):
	""" A class to validate identity providers """

	class Meta:
		model = IdentityProvider
		exclude = ('user',)



class PreAuthedForm(forms.Form):
	""" A class to validate identity providers """

	provider = forms.ChoiceField(choices=PROVIDER_CHOICES)
	token = forms.CharField(max_length=160)