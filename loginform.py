from wtforms import Form, StringField, TextAreaField, validators,SelectField,PasswordField
import shelve
from wtforms.validators import ValidationError
class CreateLoginUserForm(Form):


    Username = StringField('Username:', [validators.Length(min=1, max=150), validators.DataRequired()])
    Phone_Number = StringField('Phone Number:', [validators.DataRequired(),validators.Regexp(regex='\d{4}[-.\s]?\d{4}$',message='phone number can only have 8 digit !'),validators.Regexp(regex='[0-9]',message='Only numeric number')])
    NRIC=StringField('Nric: ',[validators.DataRequired()])
    Email=StringField('Email Address: ',[validators.DataRequired()])
    Security_Questions = SelectField('Security Questions:', [validators.DataRequired()],
                           choices=[('', 'Question 1 (Select One)'), ('Where were you when you had your first kiss? ', 'Where were you when you had your first kiss?'),
                                    ('What was your childhood nickname?', 'What was your childhood nickname?'),
                                    ('In what city did you meet your spouse/significant other?', 'In what city did you meet your spouse/significant other?'),
                                    ('What is the name of your favorite childhood friend?', 'What is the name of your favorite childhood friend?'),
                                    ('What street did you live on in third grade?', 'What street did you live on in third grade?'),
                                    ('What is your oldest sibling’s birthday month and year? (e.g., January 1999)', 'What is your oldest sibling’s birthday month and year? (e.g., January 1999)'),
                                    ('What is the middle name of your youngest child?', 'What is the middle name of your youngest child?')], default='')
    Answers=StringField('Question 1 Answer: ',[validators.DataRequired()])
    Password = PasswordField('Account Password:', [validators.DataRequired()])
    Address=TextAreaField('address:',[validators.DataRequired()])
    role=StringField('Role',default='Guest',render_kw = {'readonly':True})





