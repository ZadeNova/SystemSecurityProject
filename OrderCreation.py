class Orders:
    def __init__(self, ID, Quantity, Date,ExpectedDeliveryDate, Supplier):
        self.__ID = ID
        self.__Quantity = Quantity
        self.__Date = Date
        self.__Supplier = Supplier
        self.__ExpectedDeliveryDate = ExpectedDeliveryDate

    def get_ID(self):
        return self.__ID

    def get_Quantity(self):
        return self.__Quantity

    def get_Date(self):
        return self.__Date

    def get_Supplier(self):
        return self.__Supplier

    def get_ExpectedDeliveryDate(self):
        return self.__ExpectedDeliveryDate

    def set_ID(self, ID):
        self.__ID = ID

    def set_Quantity(self, Quantity):
        self.__Quantity = Quantity

    def set_Date(self, Date):
        self.__Date = Date

    def set_Supplier(self, Supplier):
        self.__Supplier = Supplier

    def set_ExpectedDeliveryDate(self,ExpectedDeliveryDate):
        self.__ExpectedDeliveryDate = ExpectedDeliveryDate
    def __str__(self):
        S = "{} {}".format(self.__ID,self.__Supplier,self.__Quantity)
        return S
