from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, ValidationError, validators, \
    IntegerField, FileField
import shelve
from wtforms.validators import ValidationError


class AddInventoryForm(Form):
    ID = IntegerField('ID', [validators.DataRequired(), validators.NumberRange(min=1)])
    Name = StringField('Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    Unit_of_Measure = SelectField('Unit_of_Measure', [validators.DataRequired()],
                                  choices=[('', 'Select'), ('Kilogram', 'Kg'), ('Grams', 'g')])
    Category = SelectField('Category', [validators.DataRequired()],
                           choices=[('', 'Select'), ('Meat', 'Meat'), ('Dairy', 'Dairy'),
                                    ('Condiments', 'Condiments'), ('Necessities', 'Necessities'), ('Fruits', 'Fruits')])
    Threshold = IntegerField('Threshold', [validators.NumberRange(min=1), validators.DataRequired()])
    Quantity = IntegerField('Quantity', [validators.NumberRange(min=1), validators.DataRequired()],
                            render_kw={"placeholder": "Enter amount of Inventory item"})
    Status = SelectField('Status', [validators.DataRequired()],
                         choices=[('', 'Select'), ('Available', 'Available'), ('Inactive', 'Inactive')])

    def validate_ID(self, ID):
        db = shelve.open('InventoryDB', 'r')
        InvID = {}
        InvID = db["Inventory"]
        IDList = []
        db.close()
        for id in InvID:
            IDList.append(id)
        if ID.data in IDList:
            raise ValidationError("ID already exists in database.Try another ID!")

    def validate_Name(self,Name):
        db = shelve.open('InventoryDB', 'r')
        InvName = {}
        InvName = db["Inventory"]
        InvList = []
        for id in InvName:
            inventory = InvName.get(id)
            InvList.append(inventory)
        Namelist = []
        for i in InvList:

            Namelist.append(i.get_Name())

        db.close()
        for i in Name.data:
            if i.isdigit():
                raise ValidationError("Name cannot contain numbers!")
        if Name.data in Namelist:
            raise ValidationError("Name already exists in inventory Database!")




