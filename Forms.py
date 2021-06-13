from wtforms import Form, StringField, TextAreaField, validators,SelectField,MultipleFileField
import datetime

class CreateUserForm(Form):
    y=datetime.datetime.today()
    xy=y.strftime('%d-%m-%Y')
    y2=datetime.date.today() + datetime.timedelta(days=1)
    y2z=y2.strftime('%d-%m-%Y')
    y3 = datetime.date.today() + datetime.timedelta(days=2)
    y3z = y3.strftime('%d-%m-%Y')
    y4 = datetime.date.today() + datetime.timedelta(days=3)
    y4z = y4.strftime('%d-%m-%Y')
    y5 = datetime.date.today() + datetime.timedelta(days=4)
    y5z = y5.strftime('%d-%m-%Y')
    y6 = datetime.date.today() + datetime.timedelta(days=5)
    y6z = y6.strftime('%d-%m-%Y')
    y7 = datetime.date.today() + datetime.timedelta(days=6)
    y7z = y7.strftime('%d-%m-%Y')
    y8 = datetime.date.today() + datetime.timedelta(days=7)
    y8z = y8.strftime('%d-%m-%Y')

    username = StringField('Username:',render_kw = {'readonly':True})
    date = SelectField("Date :",choices=[(xy),y2z,y3z,y4z,y5z,y6z,y7z,y8z])
    no_ppl = SelectField('Number Of People:',[validators.DataRequired()],choices=[('', 'Select'), ('1 ', '1 person'), ('2', '2 person'),('3', '3 person'),('4', '4 person'),('5', '5 person'),('6', '6 person'),('7', '7 person'),('8', '8 person')], default='')
    phone_no = StringField('Phone Number:', [validators.DataRequired(),validators.Regexp(regex='\d{4}[-.\s]?\d{4}$',message='phone number can only have 8 digit !'),validators.Regexp(regex='[0-9]',message='Only numeric number')])
    table_no =SelectField('Table Number:')
    booking_time = SelectField('Booking Time :', [validators.DataRequired()],choices=[('', 'Select'), ('12:00pm to 1:30pm', '12pm to 1:30pm'), ('2:00pm to 3:30pm', '2pm to 3:30pm'),('4:00pm to 5:30pm', '14pm to 5.30pm'),('6:00pm to 7:30pm', '6pm to 7.30pm'),('8:00pm to 9:30pm', '8pm to 9.30pm')], default='')
    status=StringField('status',render_kw={'readonly':True})
    remarks = TextAreaField('Remarks:', [validators.Optional()])






