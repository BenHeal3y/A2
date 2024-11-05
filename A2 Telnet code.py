import pexpect

# Define variables

ipaddress= '192.168.56.101'
username = 'prne'
password = 'cisco123!'

#Start the telnet session
session = pexpect.spawn('telnet '+ ipaddress, encoding ='utf-8', timeout=20)

result = session.expect(['Username:', pexpect.TIMEOUT])

if result != 0:
    print('--- Failed to create session for: ', ipaddress)
    exit()

session.sendline(username) 
result = session.expect(['Password:', pexpect.TIMEOUT]) 

if result != 0:
    print('--- Failed to enter username: ', username)
    exit()

session.sendline(password) 
result = session.expect(['#', pexpect.TIMEOUT])

if result != 0:
    print('--- Failed to enter password: ', passwordport )
    exit()

session.sendline('quit')
session.close()






