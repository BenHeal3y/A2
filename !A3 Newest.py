import pexpect




#=-------------=
#
#      A1
#
#=-------------=

def A1_ssh(ip_address, username, password_ssh, password_enable):
#Starts an SSH session
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

    #SSH Declarations
    ip_address = '192.168.56.101'
    username = 'cisco'
    password_ssh = 'cisco123!'

#Check if "Password:" was actually received   (to see if we have entered the session)
    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()
    else:
        print('Successfully created the session!')

    session.sendline(password_ssh)
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "#" was actually received   (we have entered the console)
    if result != 0:
        print('--- Failed to enter password: ', password_ssh)
        exit()
    else:
        print('Successfully entered password!')

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

    #Telnet Declarations
    ip_address = '192.168.56.101'
    password_enable = 'class123!'
    username_telnet = 'prne'
    password_telnet = 'cisco123!'

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

#=-------------=
#
#      A2
#
#=-------------=

def A2_hardening_checks(ip_address,username,password_ssh):
   
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])
    #SSH Declarations
    ip_address = '192.168.56.101'
    username = 'cisco'
    password_ssh = 'cisco123!'
   

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
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "#" was actually received   (we have entered the console)
    if result != 0:
        print('--- Failed to enter password: ', password_ssh)
        exit()
    else:
        print('Successfully entered password!')

#Getting the current running config
    session.sendline('terminal length 0')
    session.sendline('show run')
    print(session.before)
    running_config = session.before

    
    for check, rule in hardening_items.items():
        if rule in running_config:
            print(f"[PASS] {check}")
        else:
            print(f"[FAIL] {check}")
    session.close()
    return


def A2_enable_syslog(username,password_ssh,password_enable,ip_address):
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()
    else:
        print('Successfully created the session!')

    session.sendline(password_ssh)
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "#" was actually received   (we have entered the console)
    if result != 0:
        print('--- Failed to enter password: ', password_ssh)
        exit()
    else:
        print('Successfully entered password!')
    
    session.sendline("access-list 100 permit ip 192.168.56.101 0.0.0.255 any")
    print("sent access list 100 permit")
    session.sendline("access-list deny ip any any ")
    print("sent access list deny")
    session.sendline("logging host 192.168.56.101")
    print("logging host 192.168.56.101")
    session.sendline("logging trap information")
    print("logged trap information")
    print ("Configured Syslog successfully")
    session.close()

    return

#=-------------=
#
#      A3
#
#=-------------=

def A3_configure_acl(ip_address, username, password_ssh, password_enable):
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

    #SSH Declarations
    ip_address = '192.168.56.101'
    username = 'cisco'
    password_ssh = 'cisco123!'

#Check if "Password:" was actually received   (to see if we have entered the session)
    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()
    else:
        print('Successfully created the session!')

    session.sendline(password_ssh)
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "#" was actually received   (we have entered the console)
    if result != 0:
        print('--- Failed to enter password: ', password_ssh)
        exit()
    else:
        print('Successfully entered password!')
    
    print ("Configuring ACL's (Access Control List's)...")

    # Enter configuration mode
    session.sendline('configure terminal')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to enter configuration mode')
        exit()
    else:
        print('Successfully entered configuration mode!')
    


    session.sendline("ip access-list extended Inward_Traffic")  
    
    result = session.expect([r'\(config-ext-nacl\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to enter the acl')
        exit()
    else:
        print('Successfully entered the acl!')
    print("Defining a new ACL called Inward Traffic")
    
    session.sendline("permit tcp host 192.168.56.30 host 192.168.56.101 eq 22")
    result = session.expect([r'\(config-ext-nacl\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to allow traffic to the router')
        exit()
    else:
        print('Successfully Allowed traffic to the router!')


    session.sendline("permit ip 192.168.1.0 0.0.0.255 any")
    result = session.expect([r'\(config-ext-nacl\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to allow communication')
        exit()
    else:
        print('Successfully Allowed communication with any destination!')
    

    session.sendline("deny ip any any ")
    result = session.expect([r'\(config-ext-nacl\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to deny communication')
        exit()
    else:
        print('Successfully Denied any other traffic!')

    session.sendline("interface GigabitEthernet 1")
    result = session.expect([r'\(config-if\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to enter interface')
        exit()
    else:
        print('Successfully entered interface!')

    session.sendline("ip access-group Inward_Traffic in")
    result = session.expect([r'\(config-if\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to apply ACL to interface')
        exit()
    else:
        print('Successfully applied ACL to interface!')
    
    print("Assigned the ACL to GigabitEthernet 1")

    print ("Successfully configured ACL")
   
    session.sendline("exit")
    result = session.expect(['BEN#', pexpect.TIMEOUT, pexpect.EOF], timeout=20)

#Error Checks
    if result != 0:
        print('--- Failed to Go back to # mode')
        exit()
    else:
        print('Successfully Re-entered # mode!')

    session.sendline("write memory")
    print("successfully saved configuration to memory")
   
    session.close()


def A3_configure_ipsec(ip_address, username, password_ssh):
    session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
    result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

    #SSH Declarations
    ip_address = '192.168.56.101'
    username = 'cisco'
    password_ssh = 'cisco123!'

#Check if "Password:" was actually received   (to see if we have entered the session)
    if result != 0:
        print('--- Failed to create session for: ', ip_address)
        exit()
    else:
        print('Successfully created the session!')

    session.sendline(password_ssh)
    result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

#Check if "#" was actually received   (we have entered the console)
    if result != 0:
        print('--- Failed to enter password: ', password_ssh)
        exit()
    else:
        print('Successfully entered password!')
    
    print ("Configuring ACL's (Access Control List's)...")

    # Enter configuration mode
    session.sendline('configure terminal')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])

#Error Checks
    if result != 0:
        print('--- Failed to enter configuration mode')
        exit()
    else:
        print('Successfully entered configuration mode!')

#Initiates the security policy with priority of 10
    session.sendline("crypto isakmp policy 10")
    result = session.expect([r'\(config-isakmp\)#', pexpect.TIMEOUT, pexpect.EOF])

    #Error Checks
    if result != 0:
        print('--- Failed to initiate isakmp')
        exit()
    else:
        print('Successfully initiated isakmp!')

#Choose to use Advanced Encryption Standard
    session.sendline("encryption aes")
    result = session.expect([r'\(config-isakmp\)#', pexpect.TIMEOUT, pexpect.EOF])

    #Error Checks
    if result != 0:
        print('--- Failed to choose Advanced Encryption Standard')
        exit()
    else:
        print('Successfully chose Advanced Encryption Standard!')    

#choosing which hashing to use
    session.sendline("hash sha256")
    result = session.expect([r'\(config-isakmp\)#', pexpect.TIMEOUT, pexpect.EOF])

    #Error Checks
    if result != 0:
        print('--- Failed to choose sha-256 as encryption type ')
        exit()
    else:
        print('Successfully chose encryption algorithm!')
    
#creating the encryption key
    session.sendline("authentication pre-share")
    result = session.expect([r'\(config-isakmp\)#', pexpect.TIMEOUT, pexpect.EOF])

    #Error Checks
    if result != 0:
        print('--- Failed to create encryption key')
        exit()
    else:
        print('Successfully created encryption keys!')

#go back to the config mode
    session.sendline("exit")
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to re-enter config mode')
        exit()
    else:
        print('Successfully re-entered config mode!')

#define which peer device to use this key
    session.sendline('crypto isakmp key MY_KEY address 192.168.1.1')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to create encryption ke')
        exit()
    else:
        print('Successfully created encryption keys!')

#
    session.sendline('crypto ipsec transform-set MY_TRANSFORM_SET esp-aes esp-sha-hmac')
    result = session.expect([r'\(cfg-crypto-trans\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to configure encryption key')
    else:
        print('Successfully configured encryption key!')


    session.sendline('access-list 110 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')
    session.sendline('crypto map MY_CRYPTO_MAP 10 ipsec-isakmp')
    result = session.expect([r'\(config-crypto-map\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')

    session.sendline('set peer 192.168.2.1')  
    result = session.expect([r'\(config-crypto-map\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')

    session.sendline('set transform-set MY_TRANSFORM_SET') 
    result = session.expect([r'\(config-crypto-map\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')
    session.sendline('match address 110') 
    result = session.expect([r'\(config-crypto-map\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')
    session.sendline('exit')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')

    session.sendline('interface gigabitEthernet 0/1')
    result = session.expect([r'\(config-if\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')
    session.sendline('crypto map MY_CRYPTO_MAP')
    result = session.expect([r'\(config-if\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')
    session.sendline('exit')
    result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
    #Error Checks
    if result != 0:
        print('--- Failed to ')
        exit()
    else:
        print('Successfully !')

    print("IPSec configuration complete.")

    session.close()

#=-------------=
#
#     Main
#
#=-------------=




def main():
    #Delarations
    ip_address = '192.168.56.101'
    username = 'cisco'
    password_ssh = 'cisco123!'
    password_enable = 'class123!'
    
    while True:
        print("Select the connection type you would like:")
        print("1. SSH session")
        print("2. Telnet session")
        print("3. Compare the running config to hardening guide")
        print("4. Enable syslog")
        print("5. Configure An ACL ")
        print("6. Configure IPSec")
        print("x. Exit")
        choice = input ("Enter your choice (1/2/3/4/5/6/x):")

        if choice == "1":
            A1_ssh(ip_address, username, password_ssh, password_enable)
        elif choice == "2":
            A1_telnet(ip_address, username, password_ssh, password_enable)
        elif choice == "3":
            A2_hardening_checks(ip_address,username,password_ssh)
        elif choice == "4":
            A2_enable_syslog(username,password_ssh,password_enable,ip_address)
        elif choice == "5":
            A3_configure_acl(ip_address, username, password_ssh, password_enable)
        elif choice == "6":
           A3_configure_ipsec(ip_address, username, password_ssh, password_enable)
        elif choice == "x":
            print("Exiting... Goodbye!")
            break
        else:
            print("Invalid choice, try again.")
if __name__ == '__main__':
    main()
