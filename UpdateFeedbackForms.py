from wtforms import Form, StringField, SelectField, TextAreaField, validators


class CreateUpdateFeedbackForm(Form):
    category = SelectField('Category', [validators.DataRequired()],
                           choices=[('', 'Select'), ('F', 'Food'), ('S', 'Service'), ('H', 'Hygiene'),
                                    ('A', 'Ambience'), ('D', 'Delivery')], default='',render_kw = {'readonly':True})
    rating = SelectField('Ratings', [validators.DataRequired()], choices=[('1'), ('2'), ('3'), ('4'), ('5')],
                         default='',render_kw = {'readonly':True})
    contact = StringField('Contact', [validators.Length(min=1, max=8), validators.Optional()],render_kw = {'readonly':True})
    remarks = TextAreaField('Remarks', [validators.Optional()],render_kw = {'readonly':True})
    status = SelectField('Status', [validators.DataRequired()],
                         choices=[('', 'Select'), ('Open', 'Open'), ('Close', 'Close')])
