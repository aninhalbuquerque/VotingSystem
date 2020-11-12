from protocol import *

def menu_login():
    os.system('clear')
    menu = 'Digite a opcao desejada:\n1.Fazer login\n2.Cadastrar usuario\n3.Sair'
    print(menu)

    choice = raw_input('->')
    choice = str(choice)
    while choice != '1' and choice != '2' and choice != '3':
        erro = 'Entrada invalida, tente novamente.'
        print(erro)
        choice = raw_input('->')
        choice = str(choice)
    
    return choice

def user_login():
    message = 'Nome de usuario:'
    print(message)
    user = raw_input('->')
    user = str(user)
    message = 'Senha:'
    print(message)
    password = raw_input('->')
    password = str(password)
    return user, password

def user_registration():
    message = 'Usuario: '
    print(message)
    user = raw_input('->')
    user = str(user)
    message = 'Senha: '
    print(message)
    password = raw_input('->')
    password = str(password)
    message = 'Repita a senha: '
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

def vote(voting_sessions, see):
    print('Sessoes de votacao: ')
    for x in voting_sessions:
        print(' - ' + x)
    
    print('Escolha a sessao que voce gostaria de ' + see + ': ')
    choice = raw_input('->')
    while not choice in voting_sessions:
        print('Sessao nao existe. Tente novamente')
        choice = raw_input('->')
    
    return choice

def vote_options(voting_options):
    print('Opcoes: ')
    for x in voting_options:
        print(' - ' + x)
    
    print('Escolha a opcao que voce gostaria de votar: ')
    choice = raw_input('->')
    while not choice in voting_options:
        print('Opcao nao existe. Tente novamente:')
        choice = raw_input('->')
    
    return choice

def create():
    message = 'Nome da nova sessao de voto:'
    print(message)
    nome = raw_input('->')
    opcoes = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
    message = 'Quantidade de opcoes (1-9):'
    x = 0
    ret = False
    while not ret:
        print(message)
        qtOpcoes = raw_input('->')
        if not qtOpcoes in opcoes:
            message = 'Quantidade invalida. Tente novamente:'
        else:
            x = int(qtOpcoes)
            ret = True
    
    options = {}
    for i in range(1, x + 1):
        opcao = "Opcao " + str(i) + ":"
        print(opcao)
        opcao = raw_input('->')
        while opcao in options:
            print('Essa opcao ja existe. Tente novamente:')
            opcao = raw_input('->')
        options[opcao] = 0
    
    return nome, options

sock = votingsys()

sock.open_client(10000, 'localhost')
secret_key = sock.client_connection()

saiu = False 
ret = False 
while not ret:
    choice = menu_login()
    sock.send_hash(choice, sock.sock, secret_key)
    os.system('clear')

    if choice == '1':
        user, password = user_login()
        ok = sock.user_login_client(user, password, secret_key)
        while not ok:
            print('Usuario ou senha invalidos. Tente novamente.')
            user, password = user_login()
            ok = sock.user_login_client(user, password, secret_key)
        
        ret = True
    elif choice == '2':
        user, password, password2 = user_registration()
        ok, erro = sock.cadastro_client(user, password, password2, secret_key)
        while not ok:
            print(erro)
            user, password, password2 = user_registration()
            ok, erro = sock.cadastro_client(user, password, password2, secret_key)
    
    else:
        sock.close_connection(sock.sock)
        saiu = True
        ret = True

if not saiu:
    ret = False
while not ret:
    choice = menu_vote()
    sock.send_hash(choice, sock.sock, secret_key)
    os.system('clear')

    if choice == '1': #votar
        voting_sessions = sock.recv_voting_sessions(secret_key)
        session = vote(voting_sessions, 'votar')
        voting_options = sock.recv_options(session, secret_key)
        option = vote_options(voting_options)

        (ok, erro) = sock.client_vote(session, option, secret_key)

        if ok:
            print('Voto registrado com sucesso!')
        else:
            print(erro)
        print('Espere')
        cont = 0
        while cont < 40000000:
            cont = cont + 1
    
    elif choice == '2': #checar resultado
        voting_sessions = sock.recv_voting_sessions(secret_key)
        session = vote(voting_sessions, 'ver o resultado')
        ok, result = sock.client_results(session, secret_key)
        if not ok:
            print(result)
        else:
            result = eval(result)
            array = []
            for x in result:
                array.append((result[x], x))
            
            array = sorted(array, key = lambda x: (-x[0],x[1]))

            for (qtVotes, option) in array:
                print(str(option) + '  ->  ' + str(qtVotes))

        print('Espere')
        cont = 0
        while cont < 40000000:
            cont = cont + 1

    elif choice == '3': #criar
        name, options = create()
        ok = sock.client_create_session(name, options, secret_key)
        while not ok:
            print('Ja existe uma sessao com esse nome. Tente novamente')
            name, options = create()
            ok = sock.client_create_session(name, options, secret_key)
    
    else:
        sock.close_connection(sock.sock)
        ret = True
