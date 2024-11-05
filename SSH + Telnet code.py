import pexpect

# Define connection parameters
ip_address = '192.168.56.101'
username = 'cisco'
password_ssh = 'cisco123!'
password_enable = 'class123!'
username_telnet = 'prne'
password_telnet = 'cisco123!'

# Choose connection type
connection_type = input("Enter connection type (ssh/telnet): ").strip().lower()

if connection_type == 'ssh':
    # Start SSH session
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()
    else:
        print('Successfully created the session!')

    session.sendline(password_ssh)
    result = session.expect(['>', pexpect.TIMEOUT, pexpect.EOF])

    if result != 0:
        print('--- Failed to enter password: ', password_ssh)
        exit()
    else:
        print('Successfully entered password!')

    session.sendline('enable')
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

    if result != 0:
        print('--- Failed to enter enable mode')
        exit()

    # Send enable password details
    session.sendline(password_enable)
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

    if result != 0:
        print('--- Failed to enter enable mode after sending password')
        exit()
    else:
        print('Successfully entered enable mode!')

    # Enter configuration mode
    session.sendline('configure terminal')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

    if result != 0:
        print('--- Failed to enter configuration mode')
        exit()
    else:
        print('Successfully entered configuration mode!')

    session.sendline('hostname BEN')
    result = session.expect([r'BEN\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

    if result != 0:
        print('--- Failure! entering config mode')
        exit()
    else:
        print('Successfully changed the hostname!')

    session.sendline('show running-config')
    session.expect('#', timeout=30)
    
    runconfig = session.before
    with open('runningconfig.txt', "w") as file:
        file.write(runconfig)

    session.sendline('exit')
    session.close()
    print("Session ended")

elif connection_type == 'telnet':
    # Start Telnet session
    session = pexpect.spawn('telnet ' + ip_address, encoding='utf-8', timeout=20)
    result = session.expect(['Username:', pexpect.TIMEOUT])

    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()

    session.sendline(username_telnet)
    result = session.expect(['Password:', pexpect.TIMEOUT])

    if result != 0:
        print('--- Failed to enter username: ', username_telnet)
        exit()

    session.sendline(password_telnet)
    result = session.expect(['#', pexpect.TIMEOUT])

    if result == 0:
        print("--- Successfully logged in")
    else:
        print('--- Failed to enter password: ', password_telnet)
        exit()

    session.sendline('quit')
    session.close()
    print("Session ended")

else:
    print("Invalid connection type. Please enter 'ssh' or 'telnet'.")