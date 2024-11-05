import pexpect 


ip_address = '192.168.56.101'
username = 'cisco'
password = 'cisco123!'
password_enable = 'class123!'



session = pexpect.spawn('ssh ' + username + '@' + ip_address , encoding= 'utf-8', timeout=20)
result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])


if result != 0:
    print('--- Failed to create session for: ', ip_address)
    exit()
else:
    print('successfully created the session!')


session.sendline(password)
result = session.expect(['>', pexpect.TIMEOUT, pexpect.EOF])


if result != 0:
    print('--- Failed to enter password: ', password)
    exit()
else:
    print('successfully entered password!')


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
    print('successfully entered enable mode!')


# Enter configuration mode
session.sendline('configure terminal')
result = session.expect([r'.\(config\)#', pexpect.TIMEOUT, pexpect.EOF])


if result != 0:
    print('--- Failed to enter configuration mode')
    exit()
else:
    print('successfully entered configuration mode!')

session.sendline('hostname BEN')
result = session.expect([r'BEN\(config\)#', pexpect.TIMEOUT, pexpect.EOF])


if result != 0:
    print('--- Failure! entering config mode')
    exit()
else:
    print('successfully changed the hostname!')

session.sendline('show running-config')
session.expect('#', timeout=30)

runconfig = session.before
open('runningconfig.txt', "w")
f.write(runconfig)
f.close()

session.sendline('quit')
session.close()




