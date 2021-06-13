from wtforms import Form, StringField, SelectField, TextAreaField, validators


class CreateFeedbackForm(Form):
    category = SelectField('Category', [validators.DataRequired()],
                           choices=[('', 'Select'), ('F', 'Food'), ('S', 'Service'), ('H', 'Hygiene'),
                                    ('A', 'Ambience'), ('D', 'Delivery')], default='')
    rating = SelectField('Ratings', [validators.DataRequired()], choices=[('1'), ('2'), ('3'), ('4'), ('5')],
                         default='')
    contact = StringField('Contact', [validators.Length(min=1, max=8), validators.Optional()])
    remarks = TextAreaField('Remarks', [validators.Optional()])
    date = StringField('date',render_kw={'readonly':True})
