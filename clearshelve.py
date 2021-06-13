import shelve
import CreatingSupplier
InvDataBase = shelve.open('InventoryDB','c')


Order_Dict = InvDataBase['Orders']

O_dict = InvDataBase['OngoingOrders']

InvDataBase['OngoingOrders'] = O_dict

print(InvDataBase['Inventory'])

InvDataBase['Orders'] = Order_Dict
print(Order_Dict)
print(O_dict)

a = list(InvDataBase.keys())
print(a)

InvDataBase.close()