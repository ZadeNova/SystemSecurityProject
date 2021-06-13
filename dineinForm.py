from wtforms import Form, StringField, TextAreaField, validators,SelectField



class CreateDineInForm(Form):

    username = StringField('Username:', render_kw = {'readonly':True})
    no_ppl = SelectField('Number Of People:',[validators.DataRequired()],choices=[('', 'Select'), ('1 ', '1 person'), ('2', '2 person'),('3', '3 person'),('4', '4 person'),('5', '5 person'),('6', '6 person'),('7', '7 person'),('8', '8 person')], default='')
    phone_no = StringField('Phone Number:', [validators.DataRequired(),validators.Regexp(regex='\d{4}[-.\s]?\d{4}$',message='phone number can only have 8 digit !'),validators.Regexp(regex='[0-9]',message='Only numeric number')])
    table_no = SelectField('Table Number:')
    status = StringField('Status for this form :', render_kw={'readonly': True})
    time=StringField('Date :', render_kw={'readonly': True})
    remarks = TextAreaField('Remarks:', [validators.Optional()])




