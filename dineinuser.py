import shelve
class dineinuser:
        count_id = 0

        def __init__(self, username, phone_no, table_no,  remarks, no_ppl,time,status):
            ##try:
                #f = shelve.open('count.db')
                #if not ("count_id" in f):
                    #print('test')
                    #f['count_id'] = 0
            #except:
                #print('Shelve database not found!')
            #f = shelve.open('count.db')
            #f["count_id"] += 1##
            dineinuser.count_id += 1
            self.__user_id = dineinuser.count_id
            self.__username = username
            self.__time = time

            self.__status = status

            self.__phone_no = phone_no
            self.__table_no = table_no

            self.__remarks = remarks
            self.__no_ppl = no_ppl

        def set_status(self, status):
            self.__status = status

        def get_status(self):
            return self.__status

        def get_user_id(self):
            return self.__user_id

        def get_time(self):
            return self.__time

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

        def get_username(self):
            return self.__username

        def get_phone_no(self):
            return self.__phone_no

        def get_table_no(self):
            return self.__table_no

        def get_remarks(self):
            return self.__remarks

        def get_no_ppl(self):
            return self.__no_ppl

        def set_user_id(self, user_id):
            self.__user_id = user_id

        def set_time(self, time):
            self.__time = time

