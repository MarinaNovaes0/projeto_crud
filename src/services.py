import mysql.connector
from conexao import conn
import bcrypt

def enviar_dados(nome, email, senha):
    """
    Verifica se o email já está cadastrado e, caso contrário, cria um novo usuário com senha criptografada.
    """
    if verificar_email(email):
        return criar_usuario(nome, email, senha)
    return False

def verificar_email(email):
    """
    Verifica se o email já existe no banco de dados.
    Retorna True se o email não existir, permitindo o cadastro.
    """
    cursor = None
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM USUARIO WHERE email = %s', (email,))
            return cursor.fetchone() is None  # Retorna True se o email não existir
    except mysql.connector.Error as err:
        print(f'Erro: {err}')
    finally:
        if cursor is not None:
            cursor.close()
    return False

def criar_usuario(nome, email, senha):
    """
    Cadastra um novo usuário com nome, email e senha criptografada no banco de dados.
    """
    cursor = None
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            # Criptografa a senha usando bcrypt
            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
            sql = 'INSERT INTO USUARIO (nome, email, senha) VALUES (%s, %s, %s)'
            values = (nome, email, senha_hash)
            cursor.execute(sql, values)
            conn.commit()
            return True
    except mysql.connector.Error as err:
        print(f'Erro: {err}')
        return False
    finally:
        if cursor is not None:
            cursor.close()

def listar_usuario():
    """
    Retorna uma lista de todos os usuários (ID, nome, email) no banco de dados.
    """
    cursor = None
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute('SELECT ID, NOME, EMAIL FROM USUARIO;')
            usuarios = cursor.fetchall()
            return usuarios if usuarios else []
    except mysql.connector.Error as e:
        print(f'Erro: {e}')
    finally:
        if cursor is not None:
            cursor.close()
    return []

def remover_usuario(email, nome):
    """
    Remove um usuário do banco com base no email e no nome fornecidos.
    Retorna True se o usuário for encontrado e removido, False caso contrário.
    """
    cursor = None
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            sql_select = 'SELECT id, nome, email FROM USUARIO WHERE email=%s;'
            cursor.execute(sql_select, (email,))
            usuario = cursor.fetchone()

            if usuario and usuario[1].lower() == nome.lower():  # Compara o nome
                sql_delete = 'DELETE FROM USUARIO WHERE email=%s'
                cursor.execute(sql_delete, (email,))
                conn.commit()
                return True
            else:
                return False
    except mysql.connector.Error as e:
        print(f'Erro: {e}')
        return False
    finally:
        if cursor is not None:
            cursor.close()

def redefinir_senha(email, nova_senha):
    """
    Redefine a senha de um usuário com base no email fornecido.
    A nova senha é criptografada antes de ser armazenada.
    """
    cursor = None
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM USUARIO WHERE email = %s', (email,))
            usuario = cursor.fetchone()

            if usuario:
                # Criptografa a nova senha
                nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
                cursor.execute('UPDATE USUARIO SET senha = %s WHERE email = %s', (nova_senha_hash, email))
                conn.commit()
                return True
            else:
                return False
    except mysql.connector.Error as e:
        print(f'Erro: {e}')
        return False
    finally:
        if cursor is not None:
            cursor.close()

def editar_usuario(email_atual, novo_email):
    """
    Atualiza o email de um usuário existente.
    Retorna True se a atualização for bem-sucedida, False caso contrário.
    """
    cursor = None
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM USUARIO WHERE email = %s', (email_atual,))
            usuario = cursor.fetchone()

            if usuario:
                cursor.execute('UPDATE USUARIO SET email = %s WHERE email = %s', (novo_email, email_atual))
                conn.commit()
                return True
            else:
                return False
    except mysql.connector.Error as e:
        print(f'Erro: {e}')
        return False
    finally:
        if cursor is not None:
            cursor.close()

def verificar_usuario(email, senha):
    """
    Verifica o email e a senha de um usuário para login.
    A senha fornecida é comparada com o hash armazenado no banco de dados.
    """
    cursor = None
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute('SELECT senha FROM USUARIO WHERE email = %s', (email,))
            usuario = cursor.fetchone()

            if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario[0].encode('utf-8')):
                return True  # Senha correta
            else:
                return False  # Email não encontrado ou senha incorreta
    except mysql.connector.Error as e:
        print(f'Erro: {e}')
        return False
    finally:
        if cursor is not None:
            cursor.close()
