class book:
    count_id = 0
    def __init__(self, username, date, phone_no, table_no, booking_time, remarks, no_ppl,status):
        book.count_id += 1
        self.__user_id = book.count_id
        self.__username = username
        self.__date =date
        self.__phone_no = phone_no
        self.__table_no = table_no
        self.__booking_time = booking_time
        self.__remarks = remarks
        self.__no_ppl = no_ppl
        self.__status=status
    def get_status(self):
        return self.__status
    def set_status(self,status):
        self.__status=status
    def get_date(self):
        return self.__date

    def set_date(self, date):
        self.__date = date

    def get_user_id(self):
        return self.__user_id

    def set_no_ppl(self, no_ppl):
        self.__no_ppl = no_ppl

    def set_remarks(self, remarks):
        self.__remarks = remarks

    def set_username(self, username):
        self.__username = username

    def set_phone_no(self, phone_no):
        self.__phone_no = phone_no

    def set_table_no(self, table_no):
        self.__table_no = table_no

    def set_booking_time(self, booking_time):
        self.__booking_time = booking_time

    def get_username(self):
        return self.__username

    def get_phone_no(self):
        return self.__phone_no

    def get_table_no(self):
        return self.__table_no

    def get_booking_time(self):
        return self.__booking_time

    def get_remarks(self):
        return self.__remarks

    def get_no_ppl(self):
        return self.__no_ppl

    def set_user_id(self, user_id):
        self.__user_id = user_id
