class CreateLoginUser:
    count_id = 0
    def __init__(self, username,phone_no,nric,email,password,address,role):
        CreateLoginUser.count_id += 1
        self.__user_id = CreateLoginUser.count_id
        self.__username = username
        self.__address=address
        self.__phone_no = phone_no
        self.__nric=nric
        self.__email=email
        self.__password=password
        self.__role=role

    def set_password(self,password):
        self.__password=password
    def get_password(self):
        return self.__password
    def set_role(self,role):
        self.role=role
    def get_role(self):
        return self.__role
    def get_nric(self):
        return self.__nric
    def set_nric(self,nric):
        self.__nric=nric
    def set_email(self,email):
        self.__email=email
    def get_email(self):
        return self.__email



    def get_user_id(self):
        return self.__user_id


    def set_address(self, address):
        self.__address = address
    def get_address(self):
        return self.__address

    def set_username(self, username):
        self.__username = username

    def set_phone_no(self, phone_no):
        self.__phone_no = phone_no



    def get_username(self):
        return self.__username

    def get_phone_no(self):
        return self.__phone_no



    def set_user_id(self, user_id):
        self.__user_id = user_id
