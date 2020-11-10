from protocol import *

def menu_login():
    os.system('clear')
    menu = 'Digite a opcao desejada:\n1.Fazer login\n2.Cadastrar usuario\n'
    print(menu)

    choice = raw_input('->')
    choice = str(choice)
    while choice != '1' and choice != '2':
        erro = 'Entrada invalida, tente novamente.'
        print(erro)
        choice = raw_input('->')
        choice = str(choice)
    
    return choice

def user_login():
    message = 'por favor, entre com seu usuario.'
    print(message)
    user = raw_input('->')
    user = str(user)
    message = 'por favor, entre com sua senha.'
    print(message)
    password = raw_input('->')
    password = str(password)
    return user, password

def user_registration():
    message = 'Por favor, entre com o usuario que deseja cadastrar: '
    print(message)
    user = raw_input('->')
    user = str(user)
    message = 'Por favor, entre com a senha: '
    print(message)
    password = raw_input('->')
    password = str(password)
    message = 'Por favor, repita a senha: '
    print(message)
    password2 = raw_input('->')
    password2 = str(password2)
    return user, password, password2

def menu_vote():
    os.system('clear')
    menu = 'Digite a opcao desejada:\n1.Votar\n2.Checar resultado\n3.Criar sessao de voto\n4.Sair'
    print(menu)

    choice = raw_input('->')
    choice = str(choice)
    while choice != '1' and choice != '2' and choice != '3' and choice != '4':
        erro = 'Entrada invalida, tente novamente.'
        print(erro)
        choice = raw_input('->')
        choice = str(choice)
    
    return choice

def vote(voting_sections, see):
    print('sessoes de votacao: ')
    for x in voting_sections:
        print(' - ' + x)
    
    print('escolha a sessao que voce gostaria de ' + see + ': ')
    choice = raw_input('->')
    while not choice in voting_sections:
        print('sessao nao existe. tente novamente')
        choice = raw_input('->')
    
    return choice

def vote_options(voting_options):
    print('opcoes: ')
    for x in voting_options:
        print(' - ' + x)
    
    print('escolha a opcao que voce gostaria de votar: ')
    choice = raw_input('->')
    while not choice in voting_options:
        print('sessao nao existe. tente novamente')
        choice = raw_input('->')
    
    return choice

def create():
    message = 'nome da nova sessao de voto'
    print(message)
    nome = raw_input('->')
    opcoes = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
    message = 'quantidade de opcoes (1-9)'
    x = 0
    ret = False
    while not ret:
        print(message)
        qtOpcoes = raw_input('->')
        if not qtOpcoes in opcoes:
            message = 'quantidade invalida, tente novamente'
        else:
            x = int(qtOpcoes)
            ret = True
    
    options = {}
    for i in range(1, x + 1):
        opcao = "opcao " + str(i) + ":"
        print(opcao)
        opcao = raw_input('->')
        while opcao in options:
            print('essa opcao ja existe. tente novamente')
            opcao = raw_input('->')
        options[opcao] = 0
    
    return nome, options

sock = Protocol()

sock.open_client(10000)
sock.client_connection()

ret = False 
while not ret:
    choice = menu_login()
    sock.send_hash(choice, sock.sock)
    os.system('clear')

    if choice == '1':
        user, password = user_login()
        ok = sock.user_login_client(user, password)
        while not ok:
            print('Usuario ou senha invalidos. Tente novamente.')
            user, password = user_login()
            ok = sock.user_login_client(user, password)
        
        ret = True
    else:
        user, password, password2 = user_registration()
        ok, erro = sock.cadastro_client(user, password, password2)
        while not ok:
            print(erro)
            user, password, password2 = user_registration()
            ok, erro = sock.cadastro_client(user, password, password2)

ret = False
while not ret:
    choice = menu_vote()
    sock.send_hash(choice, sock.sock)
    os.system('clear')

    if choice == '1': #votar
        voting_sections = sock.recv_voting_sections()
        section = vote(voting_sections, 'votar')
        voting_options = sock.recv_options(section)
        option = vote_options(voting_options)

        sock.client_vote(section, option)
    
    elif choice == '2': #checar resultado
        voting_sections = sock.recv_voting_sections()
        section = vote(voting_sections, 'ver o resultado')
        result = sock.client_results(section)
        print(result)
        cont = 0
        while cont < 200000000:
            cont = cont + 1

    elif choice == '3': #criar
        name, options = create()
        ok = sock.client_create_session(name, options)
        while not ok:
            print('ja existe uma sessao com esse nome, tente novamente')
            name, options = create()
            ok = sock.client_create_session(name, options)
    
    else:
        sock.close_connection(sock.sock)
        ret = True

