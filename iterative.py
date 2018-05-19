"""
DNS Iterative Resolver
This program maps host names to IP addresses. It queries a server for a host name to IP address
mappings (Type A) unless given the -m flag, in which it queries for mail exchanges (Type MX).
It prints out the intermediate steps as it traverses the DNS hierarchy. If asked to resolve an
invalid name it prints an error. If the program encounters Type CNAME, then it prints out CNAME
and exits.
(Kevin Terusaki), 2013
"""
import struct
import socket
import sys

ROOT_SERVERS = ("198.41.0.4",
                "192.228.79.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

def main():
    # Get command line arguments
    args = sys.argv[1:]
    specs = []

    if len(args) == 1:
        ip_req = args[0]
        specs.append(ip_req)

    if len(args) == 2:
        opCode = args[0]
        ip_req = args[1]
        specs.append(ip_req)
        specs.append(opCode)

    # Get the root servers and their respective IP addresses
    fp = open("root-servers.txt", "r")
    root_servers = fp.readlines()
    fp.close()

    # Create a socket using transport protocol UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    port = 53

    query = makeQuery(specs)

    # Send the query
    ip_address = sendReceive(sock, port, query, root_servers, root_servers)

    print("The name", ip_req, "resolves to:",ip_address)

def sendReceive(s, port_num, question, server_list, root_servers):
    """
        Recursive function that iterates through a list of servers and queries each for an IP address
        that maps to the host name query.
        input: s, a socket
                     port_num, the DNS port
                     question, the host name
                     server_list, a list of servers that will be queried
                     root_servers, a list of root DNS servers
        return: An IP address that maps to the host name
    """
    sock = s
    port = port_num
    query = question
    new_server_list = []
    for ip_address in server_list:
        try:
            DNS_IP = ip_address
            sock.sendto(query, (DNS_IP, port))
            print("Querying server", ip_address)
            message = sock.recvfrom(1024)
            new_server_list, flag = decodeMes(message)

            # If an answer is received, return the IP Address associated with the query (base case)
            # If a list of IP addresses is returned, recursively call sendReceive using new IP addresses
            # If the type of request is MX, use the returned mail exchange as the new query
            # If the new_server_list is a list of Authoritative name servers
            # get the IP addresses of the returned name servers and send the query to the new IP Addresses
            if flag == 2:
                return new_server_list[0]

            elif flag == 1:
                return sendReceive(sock, port, query, new_server_list, root_servers)

            elif flag == 3:
                print("SOA: No such domain name")
                exit(1)

            elif flag == 4:
                specs = []
                specs.append(new_server_list[0])
                query3 = makeQuery(specs)
                return sendReceive(sock, port, query3, root_servers, root_servers)

            else:
                new_server_list2 = []
                for i in range(len(new_server_list)):
                    specs = []
                    specs.append(new_server_list[i])
                    query2 = makeQuery(specs)

                    new_server = sendReceive(sock, port, query2, root_servers, root_servers)
                    new_server_list2.append(new_server)

                return sendReceive(sock, port, query, new_server_list2, root_servers)

        except socket.timeout as e:
            print('Exception:', e)
        except socket.gaierror:
            pass


def makeQuery(specs):
    """
        Creates a standard DNS query that is sent to a DNS server
        input: specs, a list containing the requested domain name and the type of request (A or MX)
        return: message, a DNS formatted query message
    """
    size = len(specs)
    req = specs[0]

    # Create the header
    message = struct.pack('!HHHHHH', 1, 0, 1, 0, 0, 0)

    num = req.count('.')
    mylist = req.split('.')

    # Create the question and add it to the header
    for string in mylist:
        query = struct.pack("!b"+str(len(string))+"s", len(string), string.encode('utf-8'))
        message = message + query

    # If the query is Type-A otherwise it is Type-MX
    if size == 1:
        message = message + struct.pack("!bHH", 0,1,1)

    elif size == 2:
        message = message + struct.pack("!bHH", 0, 15, 1)

    return message

def decodeName(message, index):
    """
        Helper function for reading in names in the DNS message
        input: message, a DNS message from a server
                     index, the current index of the message
        return: a tuple, where the first index is the name and the second index
                        is the current index in the DNS message
    """
    print(type(message[index]))
    print(message[index])
    count, = struct.unpack("!B", b'\x03')
    index+=1

    if ((count & 0xc0) == 192):
        pointer, = struct.unpack('!B', message[index])
        index+=1
        tup = decodeName(message, pointer)
        name = tup[0]
        return (name, index)

    else:
        name = ""
        while count != 0:
            for i in range(count):
                temp_tup = struct.unpack('!s', str(message[index]).encode('utf-8'))
                temp = temp_tup[0]
                name = name + temp
                index+=1

                byte, = struct.unpack("!B", message[index])

                # Check to see if a pointer starts within a string
                if ((byte & 0xc0) == 192):
                    name = name + "."
                    index+=1
                    pointer2, = struct.unpack('!B', message[index])
                    index+=1
                    tup = decodeName(message, pointer2)
                    name = name + tup[0]
                    return (name, index)


            name = name + '.'
            count, = struct.unpack('!B', message[index])
            index+=1

        # Deleted the extra '.' at end of string
        size = len(name)
        name = name[:size-1]

        return (name, index)

def decodeMes(message):
    """
        Reads in a message of bytes that is received from a server
        input: message, a DNS message from a server
        return: a tuple, where the first index of the tuple is either a list of server names or
                        IP addresses. The second index of the tuple is a flag which helps sendReceive()
                        handle various situations
    """
    m = message[0]
    header = m[:12]
    hid, flags, QDCount, ANCount, NSCount, ARCount = struct.unpack('!HHHHHH', header)

    if ((flags % 16) == 1):
        print("Corrupt Message")
        exit(1)

    index = 12

    questionsList = []
    # Get the query
    for i in range(QDCount):
        name, index = decodeName(m, index)
        questionsList.append(name)

    # Get the Type and Class of the Question section
    Qtype, Qclass = struct.unpack('!HH', m[index:index+4])
    index +=4

    # Possible type values
    A = 1
    CNAME = 5
    SOA = 6
    MX = 15

    # Read in the Answer section
    answer_addressList = []
    for i in range(ANCount):
        name, index = decodeName(m, index)
        nameServType, nameServClass, TTL, dataLen = struct.unpack('!HHIH', m[index:index+10])
        index+=10

        # If the answer received is a CNAME, exit
        if nameServType == CNAME:
            print("CNAME found")
            exit(1)

        # If the answer is a Mail Exchange Answer
        if nameServType == MX:
            preference, = struct.unpack('!H', m[index:index+2])
            index+=2
            mail_exchange, index = decodeName(m, index)
            print(mail_exchange)
            answer_addressList.append(mail_exchange)
            return (answer_addressList, 4)

        # If the answer is a IP Address
        if nameServType == A:
            if dataLen == 4:
                ip_address1, ip_address2, ip_address3, ip_address4 = struct.unpack('!BBBB', m[index:index+4])
                ip_address = str(ip_address1)+"."+str(ip_address2)+"."+str(ip_address3)+"."+str(ip_address4)
                answer_addressList.append(ip_address)
                index+=4

    # Read in the Authoritative name servers
    nameServerList = []
    for i in range(NSCount):
        name, index = decodeName(m, index)
        nameServType, nameServClass, TTL, dataLen = struct.unpack('!HHIH', m[index:index+10])
        index += 10

        if nameServType == SOA:
            return (nameServerList, 3)

        name, index = decodeName(m, index)

        nameServerList.append(name)

    # Read in the Additional Records
    ip_addressList = []
    for i in range(ARCount):
        name, index = decodeName(m, index)
        nameServType, nameServClass, TTL, dataLen = struct.unpack('!HHIH', m[index:index+10])
        index+=10

        # Get the IP Addresses of the Authoritative name servers
        if dataLen == 4:
            ip_address1, ip_address2, ip_address3, ip_address4 = struct.unpack('!BBBB', m[index:index+4])
            ip_address = str(ip_address1)+"."+str(ip_address2)+"."+str(ip_address3)+"."+str(ip_address4)
            ip_addressList.append(ip_address)
            index+=4

    if (ANCount > 0):
        return (answer_addressList, 2)

    elif (ARCount > 0):
        return (ip_addressList, 1)

    elif (NSCount > 0):
        return (nameServerList, 0)

main()