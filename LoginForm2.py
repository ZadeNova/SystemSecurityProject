from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField,FileField,DateField,DateTimeField,PasswordField
from datetime import datetime
class Login(Form):
    UserName = IntegerField('Quantity', [validators.NumberRange(min=1),validators.DataRequired()])
    Password = PasswordField("Enter Password",[validators.DataRequired(),validators.length(min=4)])
