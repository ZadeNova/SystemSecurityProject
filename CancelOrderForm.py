from wtforms import Form, StringField, RadioField,TimeField, SelectField, TextAreaField, validators, IntegerField,FileField,DateField,DateTimeField
from datetime import datetime
from wtforms.fields.html5 import DateField
class CancelOrder(Form):
    Quantity = IntegerField('Quantity', [validators.NumberRange(min=1),validators.DataRequired()],render_kw = {'readonly':True})
    Date = DateTimeField("Date and Time", format='%d/%m/%y', default=datetime.now(),render_kw = {'readonly':True})
    ExpectedDeliveryDate = DateField("Expected Delivery Date",format='%Y-%m-%d',render_kw = {'readonly':True})
    Supplier = StringField('Supplier',[validators.DataRequired()],render_kw = {'readonly':True})
