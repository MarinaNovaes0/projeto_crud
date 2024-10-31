import mysql
import mysql.connector

conn = mysql.connector.connect(
    user= 'marina',
    host= 'localhost',
    password= 'projeto123',
    database= 'projeto_crud'   
)

if conn.is_connected():
    print('Banco de Dados conectado com sucesso!')
    
else:
    print('Não conectado com o banco!')
