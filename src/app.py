from tkinter import *
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import re
import services

def validar_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(regex, email):
        return False
    
    # Lista de domínios permitidos
    dominios_permitidos = [
        "gmail.com",
        "outlook.com",
        "yahoo.com",
        "protonmail.com",
        "zoho.com",
        "icloud.com",
        "mail.com",
        "gmx.com",
        "aol.com"
    ]
    
    # Extrai o domínio do e-mail
    dominio = email.split('@')[-1]
    
    return dominio in dominios_permitidos

def main():
    def on_enviar():
        nome = nomeEntry.get().strip()
        email = emailEntry.get().strip()
        senha = senhaEntry.get().strip()
       
        # Validações de entrada
        if not nome or not email or not senha:
            messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
            return
        
        if len(nome) < 3:
            messagebox.showerror("Erro", "O nome deve ter pelo menos 3 caracteres.")
            return
        
        if not validar_email(email):
            messagebox.showerror("Erro", "O email fornecido é inválido.")          
            return       

        if len(senha) < 8:
            messagebox.showerror("Erro", "A senha deve ter pelo menos 8 caracteres.")         
            return
        
        try:
            if not services.enviar_dados(nome, email, senha):
                messagebox.showerror("Erro", "O email fornecido já está cadastrado!")
                return

            messagebox.showinfo("Sucesso", f"Usuário {nome} cadastrado com sucesso!")
            nomeEntry.delete(0, END)
            emailEntry.delete(0, END)
            senhaEntry.delete(0, END)
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao enviar os dados: {str(e)}")

    def centralizar_janela(janela, largura=550, altura=400):
        largura_tela = janela.winfo_screenwidth()
        altura_tela = janela.winfo_screenheight()
        pos_x = (largura_tela - largura) // 2
        pos_y = (altura_tela - altura) // 2
        janela.geometry(f"{largura}x{altura}+{pos_x}+{pos_y}")

    def abrir_opcoes_administrador():
        try:
            janela_opcoes = Toplevel(janela)
            janela_opcoes.title("Opções do Administrador")
            janela_opcoes.attributes('-fullscreen', True)
            janela_opcoes.configure(bg="black")

            Label(janela_opcoes, text="Bem-Vindo!", font=('Orbitron', 64, 'bold'), bg="black", fg="white").pack(pady=20)

            options_frame = Frame(janela_opcoes, bg="black")
            options_frame.pack(pady=40)

            Button(options_frame, text="Listar Usuários", width=25, height=2, command=lambda: abrir_listar_usuarios(janela_opcoes), bg="gray", fg="black", font=('Arial', 14, 'bold')).pack(pady=10)
            Button(options_frame, text="Remover Usuário", width=25, height=2, command=lambda: abrir_remover_usuario(janela_opcoes), bg="gray", fg="black", font=('Arial', 14, 'bold')).pack(pady=10)
            Button(options_frame, text="Voltar", width=25, height=2, command=lambda: [janela_opcoes.destroy(), janela.deiconify()], bg="red", fg="white", font=('Arial', 14, 'bold')).pack(pady=10)

            img = Image.open("adm.jpg")  
            img = img.resize((800, 400), Image.LANCZOS)  
            img_tk = ImageTk.PhotoImage(img)

            label_imagem = Label(janela_opcoes, image=img_tk, bg="black")  
            label_imagem.image = img_tk  
            label_imagem.pack(side=BOTTOM, fill=X)

            frame_cantos = Frame(janela_opcoes, bg="black", height=600)
            frame_cantos.pack(side=BOTTOM, fill=BOTH, expand=True)

            centralizar_janela(janela_opcoes, largura=800, altura=600)
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao abrir as opções do administrador: {str(e)}")

    def abrir_senha_admin():
        usuarios = services.listar_usuario()
        if not usuarios:
            messagebox.showerror("Erro", "Não há usuários cadastrados.")
            return
        janela_senha = Toplevel(janela)
        janela_senha.title("Senha Necessária")
        centralizar_janela(janela_senha, 550, 400)
        janela_senha.configure(bg="#d9d9d9")

        Label(janela_senha, text="Digite a senha do administrador:", font=('Arial', 16), bg="#d9d9d9").pack(pady=20)
        senha_entry = Entry(janela_senha, width=30, show='*', font=('Arial', 16))
        senha_entry.pack(pady=10)

        def verificar_senha():
            if senha_entry.get() != 'projeto123':
                janela_senha.withdraw()
                messagebox.showerror("Erro", "Senha incorreta! Por favor, tente novamente.")
                janela_senha.deiconify()
                return   
            else:
                janela_senha.destroy()
                abrir_opcoes_administrador()
                janela.withdraw()  
                
        Button(janela_senha, text="Confirmar", width=20, command=verificar_senha, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=20)
        Button(janela_senha, text="Cancelar", command=janela_senha.destroy, width=20, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=5)

    def abrir_listar_usuarios(parent):
        usuarios = services.listar_usuario()
        if not usuarios:
            messagebox.showerror("Erro", "Não há usuários cadastrados.")
            return
        try:
            janela_listar = Toplevel(parent)
            janela_listar.title("Lista de Usuários")
            janela_listar.attributes('-fullscreen', True)
            janela_listar.configure(bg="#f0f0f5")

            Label(janela_listar, text="Usuários Cadastrados", font=('Arial', 24, 'bold'), bg="#f0f0f5").pack(pady=20)

            table_frame = Frame(janela_listar, bg="#f0f0f5")
            table_frame.pack(pady=10, padx=20, fill=BOTH, expand=True)

            tree = ttk.Treeview(table_frame, columns=('ID', 'Nome', 'Email'), show='headings')
            tree.heading('ID', text='ID')
            tree.heading('Nome', text='Nome')
            tree.heading('Email', text='Email')

            tree.column('ID', width=50, anchor=CENTER)
            tree.column('Nome', width=200, anchor=W)
            tree.column('Email', width=250, anchor=W)

            usuarios = services.listar_usuario()
            for usuario in usuarios:
                tree.insert('', END, values=usuario)

            scrollbar = Scrollbar(table_frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side="right", fill="y")

            tree.pack(fill=BOTH, expand=True)

            Button(janela_listar, text='Voltar', width=20, command=janela_listar.destroy, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=15)
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao listar usuários: {str(e)}")

    def abrir_remover_usuario(parent):
        usuarios = services.listar_usuario()
        if not usuarios:
            messagebox.showerror("Erro", "Não há usuários cadastrados.")
            return
        janela_remover = Toplevel(parent)
        janela_remover.title("Remover Usuário")
        centralizar_janela(janela_remover, 550, 400)
        janela_remover.configure(bg="#d9d9d9")

        Label(janela_remover, text="Nome:", font=('Arial', 16), bg="#d9d9d9").pack(pady=10)
        nome_entry = Entry(janela_remover, width=30, font=('Arial', 16))
        nome_entry.pack(pady=5)

        Label(janela_remover, text="Email:", font=('Arial', 16), bg="#d9d9d9").pack(pady=10)
        email_entry = Entry(janela_remover, width=30, font=('Arial', 16))
        email_entry.pack(pady=5)

        def remover_usuario():
            nome = nome_entry.get().strip()
            email = email_entry.get().strip()

            # Validações de entrada
            if not nome or not email:
                janela_remover.withdraw()
                messagebox.showerror("Erro", "Por favor, preencha os todos os campos.")
                janela_remover.deiconify()
                return

            if len(nome) < 3:
                janela_remover.withdraw()
                messagebox.showerror("Erro", "O nome deve ter pelo menos 3 caracteres.")
                janela_remover.deiconify()
                return

            if not validar_email(email):  # Função para validar formato de email
                janela_remover.withdraw()
                messagebox.showerror("Erro", "O email fornecido é inválido.")
                janela_remover.deiconify()
                return

            try:
                # Verifica se o usuário existe
                usuario = services.listar_usuario()  # Pega todos os usuários
                usuario_encontrado = any(u[1].lower() == nome.lower() and u[2].lower() == email.lower() for u in usuario)

                if not usuario_encontrado:
                    janela_remover.withdraw()
                    messagebox.showerror("Erro", "Usuário não encontrado. Verifique o nome e email.")
                    janela_remover.deiconify()
                    return

                # Tentar remover o usuário
                if services.remover_usuario(email, nome):
                    messagebox.showinfo("Sucesso", f'Usuário {nome} removido com sucesso!')
                    email_entry.delete(0, END)
                    nome_entry.delete(0, END)
                else:
                    messagebox.showerror("Erro", "Erro ao remover o usuário. Dados inválidos.")
                    email_entry.delete(0, END)
                    nome_entry.delete(0, END)
            except Exception as e:
                messagebox.showerror("Erro", f"Ocorreu um erro ao remover o usuário: {str(e)}")

        Button(janela_remover, text='Remover', command=remover_usuario, width=20, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=10)
        Button(janela_remover, text='Cancelar', command=janela_remover.destroy, width=20, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=5)


    def abrir_editar_usuario():
        usuarios = services.listar_usuario()
        if not usuarios:
            messagebox.showerror("Erro", "Não há usuários cadastrados.")
            return
        janela_editar = Toplevel(janela)
        janela_editar.title("Editar Usuário")
        centralizar_janela(janela_editar, 550, 400)
        janela_editar.configure(bg="#d9d9d9")

        Label(janela_editar, text="Email Atual:", bg="#d9d9d9", font=('Arial', 16)).pack(pady=10)
        email_atual_entry = Entry(janela_editar, width=30, font=('Arial', 16))
        email_atual_entry.pack(pady=5)

        Label(janela_editar, text="Novo Email:", bg="#d9d9d9", font=('Arial', 16)).pack(pady=10)
        novo_email_entry = Entry(janela_editar, width=30, font=('Arial', 16))
        novo_email_entry.pack(pady=5)

        def editar_usuario():
            email_atual = email_atual_entry.get().strip()
            novo_email = novo_email_entry.get().strip()

            # Validações de entrada
            if not email_atual or not novo_email:
                janela_editar.withdraw()
                messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
                janela_editar.deiconify()
                return

            if not validar_email(email_atual):
                janela_editar.withdraw()
                messagebox.showerror("Erro", "O email atual fornecido é inválido.")
                janela_editar.deiconify()
                return

            if email_atual.lower() == novo_email.lower():
                janela_editar.withdraw()
                messagebox.showerror("Erro", "O novo email deve ser diferente do email atual.")
                janela_editar.deiconify()
                return

            if not validar_email(novo_email):
                janela_editar.withdraw()
                messagebox.showerror("Erro", "O novo email fornecido é inválido.")
                janela_editar.deiconify()
                return

            try:
                # Verifica se o novo email já está cadastrado
                if not services.verificar_email(novo_email):
                    janela_editar.withdraw()
                    messagebox.showerror("Erro", "O novo email já está cadastrado.")
                    janela_editar.deiconify()
                    return

                # Tenta editar o email
                if services.editar_usuario(email_atual, novo_email):
                    janela_editar.withdraw()
                    messagebox.showinfo("Sucesso", "Email alterado com sucesso!")
                    email_atual_entry.delete(0, END)
                    novo_email_entry.delete(0, END)
                    janela_editar.deiconify()
                else:
                    janela_editar.withdraw()
                    messagebox.showerror("Erro", "Erro ao editar o email.")
                    janela_editar.deiconify()
            except Exception as e:
                janela_editar.withdraw()
                messagebox.showerror("Erro", f"Ocorreu um erro ao editar o email: {str(e)}")
                janela_editar.deiconify()

  
        Button(janela_editar, text='Salvar Alterações', command=editar_usuario, width=20, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=10)
        Button(janela_editar, text='Cancelar', command=janela_editar.destroy, width=20, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=5)

    def abrir_redefinir_senha():
        usuarios = services.listar_usuario()
        if not usuarios:
            messagebox.showerror("Erro", "Não há usuários cadastrados.")
            return
        janela_senha = Toplevel(janela)
        janela_senha.title("Redefinir Senha")
        centralizar_janela(janela_senha, 550, 400)
        janela_senha.configure(bg="#d9d9d9")

        Label(janela_senha, text="Email:", bg="#d9d9d9", font=('Arial', 16)).pack(pady=10)
        email_entry = Entry(janela_senha, width=30, font=('Arial', 16))
        email_entry.pack(pady=5)

        Label(janela_senha, text="Nova Senha:", bg="#d9d9d9", font=('Arial', 16)).pack(pady=10)
        nova_senha_entry = Entry(janela_senha, width=30, show='*', font=('Arial', 16))
        nova_senha_entry.pack(pady=5)

        Label(janela_senha, text="Confirme a Nova Senha:", bg="#d9d9d9", font=('Arial', 16)).pack(pady=10)
        conf_nova_senha_entry = Entry(janela_senha, width=30, show='*', font=('Arial', 16))
        conf_nova_senha_entry.pack(pady=5)

        def redefinir_senha():
            email = email_entry.get().strip()
            nova_senha = nova_senha_entry.get().strip()
            conf_nova_senha = conf_nova_senha_entry.get().strip()

            # Validações de entrada
            if not email or not nova_senha or not conf_nova_senha:
                janela_senha.withdraw()
                messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
                janela_senha.deiconify()
                return
            
            if len(nova_senha) < 8:
                janela_senha.withdraw()
                messagebox.showerror("Erro", "A nova senha deve ter pelo menos 8 caracteres.")
                janela_senha.deiconify()
                return
            
            if not validar_email(email):
                janela_senha.withdraw()
                messagebox.showerror("Erro", "O email fornecido é inválido.")
                janela_senha.deiconify()
                return
            
            try:

                # Verifica se a nova senha é igual à antiga
                # Para isso, você precisaria ter uma forma de obter a senha antiga. 
                # Suponha que temos uma função que pode verificar a senha antiga:
                if services.verificar_usuario(email, nova_senha):
                    janela_senha.withdraw()
                    messagebox.showerror("Erro", "A nova senha não pode ser igual à senha atual.")
                    janela_senha.deiconify()
                    return
                
                if nova_senha != conf_nova_senha:
                    janela_senha.withdraw()
                    messagebox.showerror("Erro", "As senhas não coincidem.")
                    janela_senha.deiconify()
                    return

                # Tenta redefinir a senha
                if services.redefinir_senha(email, nova_senha):
                    janela_senha.withdraw()
                    messagebox.showinfo("Sucesso", "Senha redefinida com sucesso!")
                    nova_senha_entry.delete(0, END)
                    conf_nova_senha_entry.delete(0, END)
                    janela_senha.deiconify()
                    
                else:
                    janela_senha.withdraw()
                    messagebox.showerror("Erro", "Erro ao redefinir a senha.")
                    janela_senha.deiconify()
            except Exception as e:
                janela_senha.withdraw()
                messagebox.showerror("Erro", f"Ocorreu um erro ao redefinir a senha: {str(e)}")
                janela_senha.deiconify()

        Button(janela_senha, text='Redefinir Senha', command=redefinir_senha, width=15, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=10)
        Button(janela_senha, text='Cancelar', command=janela_senha.destroy, width=15, bg="gray", height=2, font=('Arial', 12, 'bold')).pack(pady=5)


    # Janela principal
    janela = Tk()
    janela.title("Skynet")
    janela.attributes('-fullscreen', True)
    janela.configure(bg="black")

    try:
        img = Image.open("terminator_image.jpg")
        largura_tela = janela.winfo_screenwidth()
        altura_tela = janela.winfo_screenheight()
        img = img.resize((largura_tela, altura_tela), Image.LANCZOS)  
        img_tk = ImageTk.PhotoImage(img)

        label = Label(janela, image=img_tk)
        label.place(relwidth=1, relheight=1)  
    except Exception as e:
        messagebox.showerror("Erro", f"Ocorreu um erro ao carregar a imagem: {str(e)}")

    titulo = Label(janela, text='Skynet', font=('Orbitron', 80, 'bold'), bg="black", fg="white")
    titulo.place(relx=0.5, rely=0.1, anchor=CENTER)

    form_frame = Frame(janela, bg="black")
    form_frame.place(relx=0.5, rely=0.35, anchor=CENTER)

    Label(form_frame, text="Nome:", font=('Arial', 16), bg="black", fg="white").grid(row=0, column=0, sticky=W, padx=10, pady=10)
    nomeEntry = Entry(form_frame, width=30, font=('Arial', 16))
    nomeEntry.grid(row=0, column=1, padx=10, pady=10)

    Label(form_frame, text="Email:", font=('Arial', 16), bg="black", fg="white").grid(row=1, column=0, sticky=W, padx=10, pady=10)
    emailEntry = Entry(form_frame, width=30, font=('Arial', 16))
    emailEntry.grid(row=1, column=1, padx=10, pady=10)

    Label(form_frame, text="Senha:", font=('Arial', 16), bg="black", fg="white").grid(row=2, column=0, sticky=W, padx=10, pady=10)
    senhaEntry = Entry(form_frame, width=30, show='*', font=('Arial', 16))
    senhaEntry.grid(row=2, column=1, padx=10, pady=10)

    buttons_frame = Frame(janela, bg="black")
    buttons_frame.place(relx=0.5, rely=0.65, anchor=CENTER)

    Button(buttons_frame, text="Cadastrar", width=20, command=on_enviar, bg="gray", height=2, font=('Arial', 12, 'bold')).grid(row=0, column=0, padx=10, pady=5)
    Button(buttons_frame, text='Editar Usuário', width=20, command=abrir_editar_usuario, bg="gray", height=2, font=('Arial', 12, 'bold')).grid(row=0, column=1, padx=10, pady=5)
    Button(buttons_frame, text='Redefinir Senha', width=20, command=abrir_redefinir_senha, bg="gray", height=2, font=('Arial', 12, 'bold')).grid(row=0, column=2, padx=10, pady=5)

    Button(buttons_frame, text="Opções de Administrador", width=20, command=abrir_senha_admin, bg="gray", fg="black", height=2, font=('Arial', 12, 'bold')).grid(row=1, column=0, padx=10, pady=15, columnspan=2)
    Button(buttons_frame, text="Encerrar", width=20, command=janela.quit, bg="red", height=2, font=('Arial', 12, 'bold')).grid(row=1, column=1, padx=10, pady=15, columnspan=2)

    Label(buttons_frame, text="", bg="black").grid(row=2, column=0, columnspan=3, pady=10)

    janela.mainloop()

if __name__ == '__main__':
    main()
