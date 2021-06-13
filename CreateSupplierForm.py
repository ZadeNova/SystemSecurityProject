from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField, FileField, \
    DateField, DateTimeField, BooleanField
from wtforms.validators import ValidationError
import shelve


class SupplierForm(Form):
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

    def validate_ID(self, ID):
        db = shelve.open('InventoryDB', 'r')
        SupplierID = {}
        SupplierID = db["Supplier"]
        SupplierIDList = []
        db.close()
        for id in SupplierID:
            SupplierIDList.append(id)
        if ID.data in SupplierIDList:
            raise ValidationError("ID already exists in database.Try another ID!")

    def validate_PostalCode(self, PostalCode):
        for i in PostalCode.data:
            if i.isalpha():
                raise ValidationError("No alphabets in Postal Code!")
        if len(PostalCode.data) != 6:
            raise ValidationError("Postal Code must be six Numbers!")

    def validate_Handphone(self, Handphone):
        for a in Handphone.data:
            if a.isalpha():
                raise ValidationError("Phone Numbers do not contain alphabets!")
        if len(Handphone.data) != 8:
            raise ValidationError("Handphone Number must be eight Numbers!")

    def validate_BusinessName(self, BusinessName):
        db = shelve.open("InventoryDB", 'r')
        supplierdict = {}
        supplierdict = db['Supplier']
        supplierlist = []
        for key in supplierdict:
            supplier = supplierdict.get(key)
            supplierlist.append(supplier)
        suppliernamelist = []

        for i in supplierlist:
            suppliernamelist.append(i.get_BusinessName())
        if BusinessName.data in suppliernamelist:
            raise ValidationError("Supplier Name has been taken")
        elif BusinessName.data.isdigit():
            raise ValidationError("Business Name cannot contain only Numbers!")




