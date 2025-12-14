from django import forms
from django.core.validators import RegexValidator


_username_validator = RegexValidator(
    regex=r"^[a-zA-Z0-9_.-]{3,50}$",
    message="Username invalide. Utilise 3-50 caractères: lettres/chiffres/._-",
)


class RegisterForm(forms.Form):
    username = forms.CharField(
        max_length=50,
        label="Nom d'utilisateur",
        validators=[_username_validator],
        widget=forms.TextInput(attrs={"class": "input", "autocomplete": "username"}),
    )
    password1 = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={"class": "input", "autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label="Confirmez le mot de passe",
        widget=forms.PasswordInput(attrs={"class": "input", "autocomplete": "new-password"}),
    )

    def clean(self):
        cleaned = super().clean()
        p1 = (cleaned.get("password1") or "").strip()
        p2 = (cleaned.get("password2") or "").strip()

        if not p1 or not p2:
            raise forms.ValidationError("Veuillez remplir les deux champs mot de passe.")

        if len(p1) < 4:
            raise forms.ValidationError("Le mot de passe doit contenir au moins 4 caractères.")

        if p1 != p2:
            raise forms.ValidationError("Les mots de passe ne correspondent pas.")

        cleaned["password1"] = p1
        cleaned["password2"] = p2
        return cleaned
