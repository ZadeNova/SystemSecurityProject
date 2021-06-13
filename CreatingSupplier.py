class Supplier:
    def __init__(self, ID, BusinessName, Handphone, Address, PostalCode, Details,Meat,Fruits,Dairy,Condiments,Necessities):
        self.__ID = ID
        self.__BusinessName = BusinessName
        self.__HandPhone = Handphone
        self.__Address = Address
        self.__PostalCode = PostalCode
        self.__Details = Details
        self.__Meat = Meat
        self.__Fruits = Fruits
        self.__Dairy = Dairy
        self.__Condiments = Condiments
        self.__Necessities = Necessities

    def set_ID(self, ID):
        self.__ID = ID

    def set_BusinessName(self, BusinessName):
        self.__BusinessName = BusinessName

    def set_Handphone(self, Handphone):
        self.__HandPhone = Handphone

    def set_Address(self, Address):
        self.__Address = Address

    def set_PostalCode(self, PostalCode):
        self.__PostalCode = PostalCode

    def set_Details(self, Details):
        self.__Details = Details
    def set_Meat(self,Meat):
        self.__Meat = Meat
    def set_Fruits(self,Fruits):
        self.__Fruits = Fruits
    def set_Dairy(self,Dairy):
        self.__Dairy = Dairy
    def set_Condiments(self,Condiments):
        self.__Condiments = Condiments
    def set_Necessities(self,Necessities):
        self.__Necessities = Necessities

    def get_ID(self):
        return self.__ID

    def get_BusinessName(self):
        return self.__BusinessName

    def get_HandPhone(self):
        return self.__HandPhone

    def get_Address(self):
        return self.__Address

    def get_PostalCode(self):
        return self.__PostalCode

    def get_Details(self):
        return self.__Details

    def get_Meat(self):
        return self.__Meat

    def get_Fruits(self):
        return self.__Fruits

    def get_Dairy(self):
        return self.__Dairy

    def get_Condiments(self):
        return self.__Condiments

    def get_Necessities(self):
        return self.__Necessities

    def __str__(self):
        S = "Meat{} Dairy{} Fruits{} Condiments{} {}".format(self.__Meat,self.__Dairy,self.__Fruits,self.__Condiments,self.__Necessities)
        return S
