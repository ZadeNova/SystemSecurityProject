from wtforms import Form, StringField, TextAreaField, validators, SelectField, PasswordField, RadioField, DateTimeField
import shelve
from wtforms.validators import ValidationError, DataRequired
from datetime import datetime, date
from wtforms.fields.html5 import DateField, EmailField
import re
import datetime

class CreateLoginUserForm(Form):
    yy = datetime.datetime.now()
    yy = yy.replace(year=yy.year - 16)
    kkk = yy.strftime('%Y-%m-%d')

    Username = StringField('Username:', [validators.Length(min=5, max=20), validators.DataRequired()])
    NRIC = StringField('NRIC: ', validators=[validators.Regexp(regex="^[ST][0-9]{7}[A-Z]$", message='Must start with a S or T and end with any letter between A-Z')])
    DOB = DateField("Date of Birth", format='%Y-%m-%d', validators=[DataRequired('Select a date')])

   # if DOB < kkk:
        #ValidationError('wrong')
        #DOB = DateField("Date of Birth", format='%Y-%m-%d', validators=[DataRequired('Select a date')])
    #else:
        #DOB=DOB

    Gender = RadioField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ("Other", "Other")], default='')
    Password = PasswordField('Account Password:', validators=[validators.Regexp(regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$"),
        validators.EqualTo('Confirm_Password', message='Passwords must match'),
    ])
    Confirm_Password = PasswordField('Confirm Password:', validators=[
        validators.Length(min=8, max=20), validators.EqualTo('Password', message='Passwords must match')
    ])

    Phone_Number = StringField('Phone Number:', [validators.DataRequired(), validators.Regexp(regex='\d{4}[-.\s]?\d{4}$', message='Phone Number can only have 8 digits !'), validators.Regexp(regex='[0-9]', message='Only numeric number')])
    Email = EmailField('Email Address: ', [validators.DataRequired(), validators.Email()])
    Security_Questions_1 = SelectField('Security Questions:', [validators.DataRequired()],
                           choices=[('', 'Question 1 (Select One)'), ('Where were you when you had your first kiss? ', 'Where were you when you had your first kiss?'),
                                    ('What was your childhood nickname?', 'What was your childhood nickname?'),
                                    ('In what city did you meet your spouse/significant other?', 'In what city did you meet your spouse/significant other?'),
                                    ('What is the name of your favorite childhood friend?', 'What is the name of your favorite childhood friend?'),
                                    ('What street did you live on in third grade?', 'What street did you live on in third grade?'),
                                    ('What is your oldest sibling’s birthday month and year? (e.g., January 1999)', 'What is your oldest sibling’s birthday month and year? (e.g., January 1999)'),
                                    ('What is the middle name of your youngest child?', 'What is the middle name of your youngest child?')], default='')

    Answers_1 = StringField('Question 1 Answer: ', [validators.DataRequired()])
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
    Address = TextAreaField('Address:', [validators.DataRequired()])

    role = StringField('Role', default='Guest', render_kw={'readonly': True})

  #  def validate_date(self,):


