from wtforms import Form, StringField, TextAreaField, validators,SelectField,IntegerField,ValidationError,DateTimeField
import datetime

class MangDineInForm(Form):


    username = StringField('Username:', render_kw = {'readonly':True})
    no_ppl = StringField('Number Of People:', render_kw = {'readonly':True})
    phone_no = StringField('Phone Number:',  render_kw = {'readonly':True})
    table_no = StringField('Table Number:' ,render_kw = {'readonly':True})
    remarks = StringField('Remarks:',  render_kw = {'readonly':True})
    time = StringField('Date :', render_kw={'readonly': True})
    status = SelectField('Status for this form :', choices=(('waiting','waiting'),('Enter','Enter')))






