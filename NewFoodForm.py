from wtforms import Form, StringField, SelectField, TextAreaField, DecimalField, validators


class CreateFoodForm(Form):
    name = StringField('Name of Food : ', [validators.Length(min=1, max=150), validators.DataRequired()])
    image = StringField('Image of food:',[validators.Length(min=1, max=150), validators.DataRequired()])
    category = SelectField('Category : ', [validators.DataRequired()],
                           choices=[('Main dishes', 'Main dishes'), ('Side dishes', 'Side dishes'), ('Drinks', 'Drinks'), ('On Promos', 'On Promos'),
                                    ('Kids Meal', 'Kids Meal')], default='Main dishes')
    status = SelectField('Status : ', [validators.DataRequired()],
                         choices=[("Available", 'Available'), ('Unavailable', 'Unavailable')], default='Available')
    price = StringField('Price: (SGD)',[validators.DataRequired()])
    ingredients = StringField('Ingredients: ', [validators.Length(min=1, max=1000), validators.DataRequired()])
    extra_remarks = TextAreaField('Extra remarks :', [validators.Optional()])

