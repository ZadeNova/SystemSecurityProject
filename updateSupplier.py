from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField, FileField, \
    DateField, DateTimeField, BooleanField
from wtforms.validators import ValidationError
import shelve


class updateSupplierForm(Form):
    ID = IntegerField('ID', [validators.DataRequired(), validators.NumberRange(min=1)])
    BusinessName = StringField('BusinessName', validators=[validators.DataRequired(), validators.Length(min=5, max=40,
                                                                                                        message="Must be between 5 or 40 characters")])
    Address = StringField('Business Address', [validators.DataRequired(), validators.Length(min=10, max=50,
                                                                                            message="Address must be between 10 to 50 characters")])
    PostalCode = StringField('PostalCode', [validators.DataRequired()], render_kw={"placeholder": "308215"})
    Handphone = StringField('Business Phone Number', [validators.DataRequired()], render_kw={"placeholder": "96221810"})
    Details = TextAreaField('Details', [validators.optional()], render_kw={"placeholder": "Optional"})
    Meat = BooleanField("Meat")
    Fruits = BooleanField("Fruits")
    Dairy = BooleanField("Dairy")
    Condiments = BooleanField("Condiments")
    Necessities = BooleanField("Necessities")