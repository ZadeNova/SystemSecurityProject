from wtforms import Form, StringField, RadioField,TimeField, SelectField, TextAreaField, validators, IntegerField,FileField,DateField,DateTimeField
from datetime import datetime,date
from wtforms.fields.html5 import DateField
from wtforms.validators import ValidationError
class Orderupdate(Form):
    Quantity = IntegerField('Quantity', [validators.NumberRange(min=1),validators.DataRequired()])
    Date = DateTimeField("Date and Time", format='%d/%m/%y', default=datetime.now())
    ExpectedDeliveryDate = DateField("Expected Delivery Date",format='%Y-%m-%d')
    Supplier = SelectField('Supplier',[validators.DataRequired()])

    def validate_ExpectedDeliveryDate(self, ExpectedDeliveryDate):
        if ExpectedDeliveryDate.data < date.today():
            raise ValidationError("That Date is in the past,please try another Date.")
