class Feedback:
    count_id = 0

    def __init__(self, category, rating,contact, remarks,  status,date):
        Feedback.count_id += 1
        self.__no_of_feedbacks = Feedback.count_id
        self.__no_of_remarks = remarks
        self.__category = category
        self.__rating = rating
        self.__contact = contact
        self.__remarks = remarks
        self.__status = status
        self.__date = date


    def get_no_of_feedbacks(self):
        return self.__no_of_feedbacks

    def get_no_of_remarks(self):
        return self.__no_of_remarks

    def get_category(self):
        return self.__category

    def get_rating(self):
        return self.__rating

    def get_contact(self):
        return self.__contact

    def get_remarks(self):
        return self.__remarks

    def get_status(self):
        return self.__status

    def get_date(self):
        return self.__date



    def set_no_of_feedbacks(self, no_of_feedbacks):
        self.__no_of_feedbacks = no_of_feedbacks

    def set_no_of_remarks(self, no_of_remarks):
        self.__no_of_remarks = no_of_remarks

    def set_category(self, category):
        self.__category = category

    def set_rating(self, rating):
        self.__rating = rating

    def set_contact(self, contact):
        self.__contact = contact

    def set_remarks(self, remarks):
        self.__remarks = remarks

    def set_status(self, status):
        self.__status = status

    def set_date(self,date):
        self.__date = date

