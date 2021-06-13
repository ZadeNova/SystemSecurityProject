from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField,FileField

class DeliveryFormConfirm(Form):
    ID = IntegerField('ID',[validators.DataRequired(),validators.NumberRange(min=1)],render_kw = {'readonly':True})
    Quantity = IntegerField('Order Quantity', [validators.DataRequired()],render_kw = {'readonly':True})
    Supplier = StringField('Supplier', [validators.Length(min=1, max=150), validators.DataRequired()],render_kw = {'readonly':True})




