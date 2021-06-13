from wtforms import Form, StringField, TextAreaField, validators,SelectField,PasswordField
import shelve
from wtforms.validators import ValidationError
class CreateLoginUserForm(Form):


    username = StringField('Username:', [validators.Length(min=1, max=150), validators.DataRequired()])
    phone_no = StringField('Phone Number:', [validators.DataRequired(),validators.Regexp(regex='\d{4}[-.\s]?\d{4}$',message='phone number can only have 8 digit !'),validators.Regexp(regex='[0-9]',message='Only numeric number')])
    nric=StringField('Nric: ',[validators.DataRequired()])
    password = PasswordField('Account Password:', [validators.DataRequired()])
    address=TextAreaField('address:',[validators.DataRequired()])
    role=StringField('Role',default='Guest',render_kw = {'readonly':True})





