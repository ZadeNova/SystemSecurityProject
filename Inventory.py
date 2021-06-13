from flask import request


class Inventory:
    Inventory_Count = 0

    def __init__(self, ID , Name , Unit_of_Measure, Category, Threshold,Quantity, Status):

        self.__ID = ID
        self.__Name = Name
        self.__Unit_of_Measure = Unit_of_Measure
        self.__Category = Category
        self.__Threshold = Threshold
        self.__Quantity = Quantity
        self.__Status = Status


    def get_ID(self):
        return self.__ID

    def get_Name(self):
        return self.__Name

    def get_Unit_of_Measure(self):
        return self.__Unit_of_Measure

    def get_Category(self):
        return self.__Category

    def get_Threshold(self):
        return self.__Threshold

    def get_Quantity(self):
        return self.__Quantity

    def get_Status(self):
        return self.__Status




    def set_ID(self, ID):
        self.__ID = ID

    def set_Name(self, Name):
        self.__Name = Name

    def set_Unit_of_Measure(self, Unit_of_Measure):
        self.__Unit_of_Measure = Unit_of_Measure

    def set_Category(self, Category):
        self.__Category = Category

    def set_Threshold(self, Threshold):
        self.__Threshold = Threshold

    def set_Quantity(self, Quantity):
        self.__Quantity = Quantity

    def set_Status(self, Status):
        self.__Status = Status


    def __str__(self):
        S = "{}".format(self.__Name)
        return S


