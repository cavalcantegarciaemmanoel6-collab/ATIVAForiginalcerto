from flask import Flask, render_template, request, redirect, url_for, flash, session
import fdb
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta_ativa_fitness'
bcrypt = Bcrypt(app)


# Conexão com o banco
host = 'localhost'
database = r'C:\Users\Aluno\Downloads\BancoDados\TRABALHOATFIT.FDB'
user = 'sysdba'
password = 'sysdba'

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)


# Landing page
@app.route('/')
def home():
    return render_template('landingpage.html')


# Função senha forte
def senha_forte(senha):

    if len(senha) < 8:
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_especial = False

    for caractere in senha:

        if caractere.isupper():
            tem_maiuscula = True

        elif caractere.islower():
            tem_minuscula = True

        elif caractere.isdigit():
            tem_numero = True

        else:
            tem_especial = True

    return (tem_maiuscula and tem_minuscula and tem_numero and tem_especial)


# Cadastrar novo usuário
@app.route('/novo_usuario', methods=['GET', 'POST'])
def novo_usuario():

    # Exibir formulário
    if request.method == 'GET':
        return render_template('novo_usuario.html')

    # Receber dados do formulário
    nome = request.form.get('nome', '').strip()
    email = request.form.get('email', '').strip()
    senha = request.form.get('senha', '')
    confirmar_senha = request.form.get('confirmar_senha', '')

    # Verificação campos preenchidos
    if not nome or not email or not senha or not confirmar_senha:

        flash('Preencha todos os campos.', 'erro')
        return redirect(url_for('novo_usuario'))

    # Verificação da força da senha
    if not senha_forte(senha):
        flash(
            'A senha deve ter pelo menos 8 caracteres, '
            'uma letra maiúscula, uma letra minúscula, '
            'um número e um caractere especial.', 'erro'
        )

        return redirect(url_for('novo_usuario'))

    # Verificação se as senhas são iguais
    if senha != confirmar_senha:
        flash('As senhas não são iguais.', 'erro')
        return redirect(url_for('novo_usuario'))

    cursor = con.cursor()

    try:

        # Verificação de e-mail já cadastrado
        cursor.execute(
            """
            SELECT id_usuario FROM USUARIO WHERE email = ?
            """,
            (email,)
        )

        usuario_existente = cursor.fetchone()

        if usuario_existente:

            flash('Este e-mail já está cadastrado.', 'erro')
            return redirect(url_for('novo_usuario'))

        # Criptografar a senha
        senha_hash = bcrypt.generate_password_hash(
            senha
        ).decode('utf-8')

        # Cadastrar usuário
        cursor.execute(
            """
            INSERT INTO USUARIO(nome, email, senha, tentativas, ativo)
            VALUES (?, ?, ?, ?, ?)
            """,
            (nome, email, senha_hash, 0, 1)
        )

        # Salvar no banco
        con.commit()

        flash('Usuário cadastrado com sucesso!', 'sucesso')

        return redirect(url_for('login'))

    # Tratar erros
    except Exception as e:

        con.rollback()

        flash(f'Erro ao cadastrar usuário: {e}', 'erro')

        return redirect(url_for('novo_usuario'))

    # Fechar o cursor
    finally:
        cursor.close()


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():

    # Se o formulário foi enviado
    if request.method == 'POST':

        # Pegar os dados enviados pelo formulário
        email = request.form.get('email')
        senha = request.form.get('senha')

        # Verificar se os campos foram preenchidos
        if not email or not senha:

            flash('Preencha o email e a senha.', 'erro')
            return redirect(url_for('login'))

        cursor = con.cursor()

        try:

            # Buscar usuário pelo e-mail
            cursor.execute(
                """
                SELECT
                    id_usuario,
                    nome,
                    email,
                    senha,
                    tentativas,
                    ativo
                FROM USUARIO
                WHERE email = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            # Usuário não encontrado
            if not usuario:

                flash('Email ou senha incorretos.', 'erro')
                return redirect(url_for('login'))

            # Organizar dados do usuário
            (
                id_usuario,
                nome,
                email_banco,
                senha_hash,
                tentativas,
                ativo
            ) = usuario

            # Caso tentativas esteja NULL no banco
            if tentativas is None:
                tentativas = 0

            # Verificar se o usuário está ativo
            if ativo == 0:

                flash('Usuário inativo ou bloqueado.', 'erro')
                return redirect(url_for('login'))

            # Verificar senha
            if bcrypt.check_password_hash(senha_hash, senha):

                # Guardar os dados na sessão
                session['id_usuario'] = id_usuario
                session['usuario_nome'] = nome
                session['usuario_email'] = email_banco

                # Zerar as tentativas
                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET tentativas = ?
                    WHERE id_usuario = ?
                    """,
                    (0, id_usuario)
                )

                con.commit()

                flash('Login realizado com sucesso!', 'sucesso')

                return redirect(url_for('index'))

            # Senha incorreta
            tentativas += 1

            # Bloquear após 3 tentativas
            if tentativas >= 3:

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET tentativas = ?, ativo = ?
                    WHERE id_usuario = ?
                    """,
                    (tentativas, 0, id_usuario)
                )

                con.commit()

                flash('Usuário bloqueado após 3 tentativas.', 'erro')

                return redirect(url_for('login'))

            # Atualizar tentativas
            cursor.execute(
                """
                UPDATE USUARIO
                SET tentativas = ?
                WHERE id_usuario = ?
                """,
                (tentativas, id_usuario)
            )

            con.commit()

            flash(
                f'Email ou senha incorretos. '
                f'Tentativa {tentativas} de 3.', 'erro'
            )

            return redirect(url_for('login'))

        # Erro no banco ou no login
        except Exception as e:

            con.rollback()

            flash(f'Ocorreu um erro no login: {e}', 'erro')

            return redirect(url_for('login'))

        finally:
            cursor.close()

    return render_template('login.html')


# Início / Dashboard
@app.route('/inicio')
def index():

    # Verificar se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Pegar o nome do usuário
    nome = session['usuario_nome']

    return render_template('dashboard.html', nome=nome)



# Editar perfil
@app.route('/editar_perfil', methods=['GET', 'POST'])
def editar_perfil():

    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    id_usuario = session['id_usuario']

    # Utiliza a conexão global com o banco
    cursor = con.cursor()

    if request.method == 'POST':

        # Recebe os dados do formulário
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')
        senha2 = request.form.get('senha2', '')

        try:
            # Verifica se nome e e-mail foram preenchidos
            if not nome or not email:
                flash('Preencha o nome e o e-mail.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Verifica se o e-mail já pertence a outro usuário
            cursor.execute("""
                SELECT id_usuario
                FROM USUARIO
                WHERE email = ? AND id_usuario <> ?
            """, (email, id_usuario))

            if cursor.fetchone():
                flash('Este e-mail já está cadastrado.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Verifica se o usuário quer alterar a senha
            if senha or senha2:

                # Exige o preenchimento dos dois campos
                if not senha or not senha2:
                    flash('Preencha os dois campos de senha.', 'erro')
                    return redirect(url_for('editar_perfil'))

                # Primeiro, verifica se a senha é forte
                if not senha_forte(senha):
                    flash(
                        'A senha deve ter pelo menos 8 caracteres, '
                        'uma letra maiúscula, uma letra minúscula, '
                        'um número e um caractere especial.',
                        'erro'
                    )
                    return redirect(url_for('editar_perfil'))

                # Depois, verifica se as senhas são iguais
                if senha != senha2:
                    flash('As senhas não são iguais.', 'erro')
                    return redirect(url_for('editar_perfil'))

                # Busca a senha atual e as duas senhas anteriores
                cursor.execute("""
                    SELECT senha, senha1, senha2
                    FROM USUARIO
                    WHERE id_usuario = ?
                """, (id_usuario,))

                resultado = cursor.fetchone()

                senha_atual = resultado[0]
                senha_anterior1 = resultado[1]
                senha_anterior2 = resultado[2]

                # Compara a nova senha com a senha atual
                if senha_atual and bcrypt.check_password_hash(
                    senha_atual, senha
                ):
                    flash(
                        'Você não pode reutilizar a senha atual.',
                        'erro'
                    )
                    return redirect(url_for('editar_perfil'))

                # Compara com a primeira senha anterior
                if senha_anterior1 and bcrypt.check_password_hash(
                    senha_anterior1, senha
                ):
                    flash(
                        'Você já utilizou essa senha anteriormente.',
                        'erro'
                    )
                    return redirect(url_for('editar_perfil'))

                # Compara com a segunda senha anterior
                if senha_anterior2 and bcrypt.check_password_hash(
                    senha_anterior2, senha
                ):
                    flash(
                        'Você já utilizou essa senha anteriormente.',
                        'erro'
                    )
                    return redirect(url_for('editar_perfil'))

                # Criptografa a nova senha
                nova_senha_hash = bcrypt.generate_password_hash(
                    senha
                ).decode('utf-8')

                # Atualiza o histórico das senhas
                cursor.execute("""
                    UPDATE USUARIO
                    SET senha2 = senha1,
                        senha1 = senha,
                        senha = ?
                    WHERE id_usuario = ?
                """, (nova_senha_hash, id_usuario))

            # Atualiza o nome e o e-mail
            cursor.execute("""
                UPDATE USUARIO
                SET nome = ?, email = ?
                WHERE id_usuario = ?
            """, (nome, email, id_usuario))

            # Salva as alterações no banco
            con.commit()

            # Atualiza os dados da sessão
            session['usuario_nome'] = nome
            session['usuario_email'] = email

            flash('Perfil atualizado com sucesso!', 'sucesso')
            return redirect(url_for('editar_perfil'))

        except Exception as erro:
            con.rollback()
            print('Erro ao editar perfil:', erro)

            flash(
                'Ocorreu um erro ao atualizar o perfil.',
                'erro'
            )

            return redirect(url_for('editar_perfil'))

        finally:
            # Fecha somente o cursor, não a conexão global
            cursor.close()

    # Busca os dados atuais do usuário
    try:
        cursor.execute("""
            SELECT nome, email
            FROM USUARIO
            WHERE id_usuario = ?
        """, (id_usuario,))

        usuario = cursor.fetchone()

    finally:
        # Fecha somente o cursor
        cursor.close()

    # Exibe a página com os dados atuais
    return render_template(
        'editar_perfil.html',
        nome=usuario[0],
        email=usuario[1]
    )


# Logout
@app.route('/logout')
def logout():

    # Apagar os dados da sessão
    session.clear()

    flash('Você saiu da sua conta, com sucesso!', 'sucesso')

    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)