from wtforms import Form, StringField, TextAreaField, validators,SelectField,PasswordField,RadioField,DateTimeField
import shelve
from wtforms.validators import ValidationError,DataRequired
from datetime import datetime,date
from wtforms.fields.html5 import DateField
class UpdateUserForm(Form):


    Username = StringField('Username:', [validators.DataRequired(),validators.Regexp("^[A-Za-z][A-Za-z0-9]{4,19}$", message='Username can only consist of alphabets and numbers and must be between 5 to 20 characters')])
    NRIC=StringField('NRIC: ',[validators.DataRequired(),validators.Regexp(regex="^[ST][0-9]{7}[A-Z]$", message='Must start with a S or T and end with any letter between A-Z')])
    DOB = DateField("Date of Birth", format='%Y-%m-%d',validators=[DataRequired('Select a date'),validators.DataRequired()])
    Gender = RadioField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'),("Other","Other")], default='')
    Phone_Number = StringField('Phone Number:',[validators.DataRequired(), validators.Regexp(regex='^[8-9][0-9]{7}$', message='Phone Number can only have 8 digits and must begin with a 8 or 9!'), validators.Regexp(regex='[0-9]', message='Only numeric number')])
    Email=StringField('Email Address: ',validators=[validators.DataRequired(),validators.Regexp(regex='^[A-Za-z0-9.]+@[GMAIL.gmail.HOTMAIL.hotmail.YAHOO.yahoo]+\.[com]{2,}$',message='Only allow letter/number/./ @ gmail/hotmail/yahoo.com only etc test@gmail.com ')])
    Security_Questions_1 = SelectField('Security Questions:', [validators.DataRequired()],
                           choices=[('', 'Question 1 (Select One)'), ('Where were you when you had your first kiss? ', 'Where were you when you had your first kiss?'),
                                    ('What was your childhood nickname?', 'What was your childhood nickname?'),
                                    ('In what city did you meet your spouse/significant other?', 'In what city did you meet your spouse/significant other?'),
                                    ('What is the name of your favorite childhood friend?', 'What is the name of your favorite childhood friend?'),
                                    ('What street did you live on in third grade?', 'What street did you live on in third grade?'),
                                    ('What is your oldest sibling’s birthday month and year? (e.g., January 1999)', 'What is your oldest sibling’s birthday month and year? (e.g., January 1999)'),
                                    ('What is the middle name of your youngest child?', 'What is the middle name of your youngest child?')], default='')


    Answers_1=StringField('Question 1 Answer: ',[validators.DataRequired()])
    Security_Questions_2 = SelectField('Security Questions:', [validators.DataRequired()],
                                       choices=[('', 'Question 2 (Select One)'), (
                                       'What school did you attend for sixth grade? ',
                                       'What school did you attend for sixth grade?'),
                                                ('What was your childhood phone number including area code? (e.g., 000-000-0000)',
                                                 'What was your childhood phone number including area code? (e.g., 000-000-0000)'),
                                                ("What is your oldest cousin's first and last name?",
                                                 "What is your oldest cousin's first and last name?"),
                                                ('What was the name of your first stuffed animal?',
                                                 'What was the name of your first stuffed animal?'),
                                                ('In what city or town did your mother and father meet?',
                                                 'In what city or town did your mother and father meet?'),
                                                (
                                                'What was the last name of your third grade teacher?',
                                                'What was the last name of your third grade teacher?'),
                                                ('In what city does your nearest sibling live?',
                                                 'In what city does your nearest sibling live?')], default='')
    Answers_2 = StringField('Question 2 Answer: ', [validators.DataRequired()])
    Address=TextAreaField('Address:',[validators.DataRequired(), validators.Regexp(regex='^[^@!$%^&*()<>{}\"/\'\[\]\|?+=_]+$', message='Enter only alphabets and numbers, do not enter special characters/symbols!')])

    role=StringField('Role',default='Guest',render_kw = {'readonly':True})