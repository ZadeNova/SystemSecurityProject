from wtforms import Form, validators,SelectField

class Createmangetable(Form):
    table_no = SelectField('Table Number:', [validators.DataRequired()],
                           choices=[('', 'Select'), ('table 1 ', 'table 1'), ('table 2', 'table 2'), ('table 3', 'table 3'),
                                    ('table 4', 'table 4'), ('table 5', 'table 5'), ('table 6', 'table 6'), ('table 7', 'table 7'),
                                    ('table 8', 'table 8'), ('table 9', 'table 9'), ('table 10', 'table 10'), ('table 11', 'table 11'),
                                    ('table12', 'table 12'), ('table 13', 'table 13'), ('table 14', 'table 14'), ('table 15', 'table 15'),
                                    ('table 16', 'table 16'), ('table 17', 'table 17'), ('table 18', 'table 18'), ('table 19', 'table 19'),
                                    ('table 20', 'table 20'),('out of table please wait',('out of table please wait'))], default='')
    remarks=SelectField('Status for this table ',[validators.DataRequired()],choices=[('active','active'),('inactive','inactive')])


