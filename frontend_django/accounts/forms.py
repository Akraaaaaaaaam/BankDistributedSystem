from django import forms
from django.core.validators import RegexValidator

_username_validator = RegexValidator(
    regex=r"^[a-zA-Z0-9_.-]{3,50}$",
    message="Username invalide. Utilise 3-50 caractères: lettres/chiffres/._-",
)

_cin_validator = RegexValidator(
    regex=r"^[A-Za-z0-9]{3,20}$",
    message="CIN invalide (3-20 caractères alphanumériques).",
)

_phone_validator = RegexValidator(
    regex=r"^[0-9+()\s.-]{6,30}$",
    message="Téléphone invalide.",
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

    # NEW — infos client
    first_name = forms.CharField(
        max_length=100,
        label="Prénom",
        widget=forms.TextInput(attrs={"class": "input", "autocomplete": "given-name"}),
    )
    last_name = forms.CharField(
        max_length=100,
        label="Nom",
        widget=forms.TextInput(attrs={"class": "input", "autocomplete": "family-name"}),
    )
    cin = forms.CharField(
        max_length=20,
        label="CIN",
        validators=[_cin_validator],
        widget=forms.TextInput(attrs={"class": "input"}),
    )
    email = forms.EmailField(
        required=False,
        max_length=150,
        label="Email",
        widget=forms.EmailInput(attrs={"class": "input", "autocomplete": "email"}),
    )
    phone = forms.CharField(
        required=False,
        max_length=30,
        label="Téléphone",
        validators=[_phone_validator],
        widget=forms.TextInput(attrs={"class": "input", "autocomplete": "tel"}),
    )
    address = forms.CharField(
        required=False,
        max_length=255,
        label="Adresse",
        widget=forms.TextInput(attrs={"class": "input", "autocomplete": "street-address"}),
    )

    branch_id = forms.ChoiceField(
        choices=[],
        label="Agence",
        widget=forms.Select(attrs={"class": "select"}),
    )

    def __init__(self, *args, branches=None, **kwargs):
        super().__init__(*args, **kwargs)
        branches = branches or []
        choices = [("", "-- Sélectionnez une agence --")]
        for b in branches:
            # b attendu: {"id":..,"code":..,"name":..,"city":..}
            choices.append((str(b["id"]), f'{b.get("code")} - {b.get("name")} ({b.get("city")})'))
        self.fields["branch_id"].choices = choices

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

        # branch obligatoire
        branch_id = (cleaned.get("branch_id") or "").strip()
        if not branch_id:
            raise forms.ValidationError("Veuillez sélectionner une agence.")

        cleaned["password1"] = p1
        cleaned["password2"] = p2
        return cleaned
