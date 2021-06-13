class Food:
    count = 0

    def __init__(self, food_name, image, category, status, price, ingredients, extra_remarks):
        Food.count += 1
        self.__id = Food.count
        self.__food_name = food_name
        self.__image = image
        self.__category = category
        self.__status = status
        self.__price = price
        self.__ingredients = ingredients
        self.__extra_remarks = extra_remarks

    def set_food_name(self, food_name):
        self.__food_name = food_name

    def set_image(self,image):
        self.__image = image

    def set_category(self, category):
        self.__category = category

    def set_status(self, status):
        self.__status = status

    def set_price(self, price):
        self.__price = price

    def set_ingredients(self, ingredients):
        self.__ingredients = ingredients

    def set_extra_remarks(self, extra_remarks):
        self.__extra_remarks = extra_remarks

    def get_id(self):
        return self.__id

    def get_food_name(self):
        return self.__food_name

    def get_image(self):
        return self.__image

    def get_category(self):
        return self.__category

    def get_status(self):
        return self.__status

    def get_price(self):
        return self.__price

    def get_ingredients(self):
        return self.__ingredients

    def get_extra_remarks(self):
        return self.__extra_remarks
