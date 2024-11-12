import pexpect



def A1_ssh(ip_address, username, password_ssh, password_enable):
#Starts an SSH session
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])


#Check if "Password:" was actually received   (to see if we have entered the session)
    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()
    else:
        print('Successfully created the session!')



    session.sendline(password_ssh)
    result = session.expect(['>', pexpect.TIMEOUT, pexpect.EOF])

#Check if ">" was actually received   (we have entered the console)
    if result != 0:
        print('--- Failed to enter password: ', password_ssh)
        exit()
    else:
        print('Successfully entered password!')



    session.sendline('enable')
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

#Check if (enable) "Password:" was actually received   (enable was entered)
    if result != 0:
        print('--- Failed to enter enable mode')
        exit()



# Send enable password details
    session.sendline(password_enable)
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "#" was actually received   (we entered enable mode)
    if result != 0:
        print('--- Failed to enter enable mode after sending password')
        exit()
    else:
        print('Successfully entered enable mode!')



# Enter configuration mode
    session.sendline('configure terminal')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "(config)#" was actually received   (we entered configuration mode)
    if result != 0:
        print('--- Failed to enter configuration mode')
        exit()
    else:
        print('Successfully entered configuration mode!')



#sends a command to rename the router
    session.sendline('hostname BEN')
    result = session.expect([r'BEN\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "BEN(config)#" was actually received   (the router was renamed)
    if result != 0:
        print('--- Failure! entering config mode')
        exit()
    else:
        print('Successfully changed the hostname!')


#exits config mode so we can easily enter "show runningconfig"
    session.sendline('exit')




#sends a command to receive running config
    session.sendline('show running-config')
    session.expect('#', timeout=30)
    
#takes the running configuration and writes it to a new file called runningconfig.txt
    runconfig = session.before
    with open('runningconfig.txt', "w") as file:
        file.write(runconfig)

#ends the session
    session.sendline('exit')
    session.close()
    print("Session ended")
    return

def A1_telnet(ip_address, username_telnet, password_telnet, password_enable):
#starts the telnet session
    session = pexpect.spawn('telnet ' + ip_address, encoding='utf-8', timeout=20)
    result = session.expect(['Username:', pexpect.TIMEOUT, pexpect.EOF])

#Check if "Username:" was actually received   (we entered the telnet session)
    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()



#sends the username of the telnet session
    session.sendline(username_telnet)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

#Check if "Password:" was actually received   (we entered the username correctly)
    if result != 0:
        print('--- Failed to enter username: ', username_telnet)
        exit()



#sends the telnet password
    session.sendline(password_telnet)
    result = session.expect(['>', pexpect.TIMEOUT, pexpect.EOF])

#Check if ">" was actually received   (we successfully entered the telnet session)
    if result == 0:
        print("--- Successfully logged in")
    else:
        print('--- Failed to enter password: ', password_telnet)
        exit()
    


    #sends the enable to command to entere enable mode 
    session.sendline('enable')
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

#Check if "Password:" was actually received
    if result == 0:
        print("--- Successfully sent (enable)")
    else:
        print('--- Failed to enter enable')
        exit()
#sends the enable password 
    session.sendline(password_enable)
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])


#Check if "#" was actually received   (we entered enable mode)
    if result == 0:
        print("--- Successfully entered enable mode")
    else:
        print('--- Failed to enter enable mode')
        exit()
    
# Enter configuration mode
    session.sendline('configure terminal')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "(config)#" was actually received
    if result != 0:
        print('--- Failed to enter configuration mode')
        exit()
    else:
        print('Successfully entered configuration mode!')



#sends command to change the hostname 
    session.sendline('hostname BEN')
    result = session.expect([r'BEN\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "BEN(config)#" was actually received   (we successfully changed the hostname)
    if result != 0:
        print('--- Failure! entering config mode')
        exit()
    else:
        print('Successfully changed the hostname!')



#exits config mode so we can easily enter "show runningconfig"
    session.sendline('exit')



    session.sendline('show running-config')
    session.expect('#', timeout=30)
    
    runconfig = session.before
    with open('runningconfig.txt', "w") as file:
        file.write(runconfig)

    session.sendline('quit')
    session.close()
    print("Session ended")
    return

def hardening_checks(ip_address,username,password_ssh,password_enable):
   
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

 #Hardening checks
    hardening_items = {
    'SSH enabled': 'ip ssh  version 2',
    'Telnet disabled': 'no service telnet',
    'Password encryption': 'service password-encryption',
    'Logging enable': 'logging buffered',
    'NTP configured': 'ntp server'
    }

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
    
    running_config = session.sendline('show running-config')
    
    for check, rule in hardening_items.items():
        if rule in running_config:
            print(f"[PASS] {check}")
        else:
            print(f"[FAIL] {check}")
    session.close()
    return


def enable_syslog(username,password_ssh,password_enable,ip_address):
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
    
    session.sendline("access-list 100 pemit ip 192.168.56.101 0.0.0.255 any")
    session.sendline("access-list deny ip any any ")
    session.sendline("logging host 192.168.56.101")
    session.sendline("logging trap information")

    session.close()

    return

def main():
    #Delarations
    ip_address = '192.168.56.101'
    username = 'cisco'
    password_ssh = 'cisco123!'
    password_enable = 'class123!'
    username_telnet = 'prne'
    password_telnet = 'cisco123!'

    while True:
        print("Select the connection type you would like:")
        print("1. SSH session")
        print("2. Telnet session")
        print("3. Compare the running config to hardening guide")
        print("4. Enable syslog")
        print("x. Exit")
        choice = input ("Enter your choice:")

        if choice == "1":
            A1_ssh(ip_address, username, password_ssh, password_enable)
        elif choice == "2":
            A1_telnet(ip_address, username, password_ssh, password_enable)
        elif choice == "3":
            hardening_checks(ip_address,username,password_ssh,password_enable)
        elif choice == "4":
            enable_syslog(username,password_ssh,password_enable,ip_address)
        elif choice == "x":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, try again.")
if __name__ == '__main__':
    main()