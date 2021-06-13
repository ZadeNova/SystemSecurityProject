class mangetable1:
    count_id = 0

    def __init__(self,  table_no, remarks):
        mangetable1.count_id += 1
        self.__user_id = mangetable1.count_id
        self.__table_no = table_no
        self.__remarks = remarks



    def set_remarks(self, remarks):
        self.__remarks = remarks

    def set_user_id(self, user_id):
        self.__user_id = user_id
    def get_user_id(self):
        return self.__user_id


    def set_table_no(self, table_no):
        self.__table_no = table_no


    def get_table_no(self):
        return self.__table_no

    def get_remarks(self):
        return self.__remarks


