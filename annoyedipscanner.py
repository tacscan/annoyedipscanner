#!/usr/bin/env python3

import threading
import os
import time
import subprocess
import concurrent.futures
import socket
import argparse
import math

parser = argparse.ArgumentParser(prog='Annoyed IP Scanner', description='Scan a network for unused IP addresses')
parser.add_argument('-s', help='Subnet in the form of A.B.C', required=True)
parser.add_argument('-f', help='Starting node octet, ex: 110 (default is 1)', default=1, required=False)
parser.add_argument('-l', help='Ending node octet, ex: 155 (default is 255', default=255,  required=False)
parser.add_argument('-p', help='Ping sweep only, not default', required=False, action='store_true')
parser.add_argument('-g', help='Port set to scan, default is nmap default eleven', choices=['1000', 'fast'], required=False)
parser.add_argument('-a', help='CSV portlist file to read in for TCP port scan (-p overrides this option)', required=False)
parser.add_argument('-b', help='One port per line portlist file to read in for TCP port scan (-p overrides this option)', required=False)
args = vars(parser.parse_args())

####################
# Print the header
####################
def printHeader():
    print('\n[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]')
    print('[*]  Annoyed IP Scanner - Sean Hall 2024  [*]')
    print('[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n')
    print(' ')

##############################################################################################################
# Test the user input parameters for validity, is the first host less than the last,
# does the subnet contain valid octets. Output warninigs and stop execution
##############################################################################################################
def parmChecks(first, last, subnet, csvFile, newline):
    if(first > last) or (first < 0) or (last > 255):
        print('[!!!] The first IP in the range (-f) should be greater than zero but less than the last IP value')
        print('      the last IP in the range (-l) should be less than 255 but greater than the first IP value')   
        print('      please check your -f and -l values')
        quit()

    #if there is not exactly 3 octets, there's something wrong with the formatting
    octets = subnet.split(".")
    if(len(octets)!= 3):
        print(octets)
        print('[!!!] Please check the format of the subnet parameter (-s), there are too many')
        print('      or too few octets or the there is an extra dot separator')
        print('      => an example would be -s 192.168.10, three octets and two dots.')
        quit()

    #separate out the first three octets for bounds checks
    octets = subnet.split(".")
    octet0 = int(octets[0])
    octet1 = int(octets[1])
    octet2 = int(octets[2])

    if (octet0 < 1 or octet0 > 255) or (octet1 < 0 or octet1 > 255) or (octet2 < 0 or octet2 > 255):
        print('[!!!] Please check the format of the subnet parameter (-s)')
        print('      one or more octets is out of bounds, none may be less')
        print('      than zero or greater than 255.') 
        quit()

    if (csvFile != None) and (newline !=None):
        print('[!!!] Please check the file parameters -a and -b)')
        print('      only one of the two parameters is allowed')
        print('      select -a for a CSV file or -b for a file with')
        print('      port numbers, one per line.')
        quit()
        
##############################################################################################################
# Print the ports read in from a file
##############################################################################################################
def printPortList(portPrint):
    rows = math.floor(len(portPrint)/9)
    leftOvers = len(portPrint)%9
    offset = 0
    temp = []

    for a in range(0, len(portPrint)):
        temp.append(portPrint[a])

    for x in range(0, 9-leftOvers):
        temp.append('     ')

    print('     +-------+-------+-------+-------+-------+-------+-------+-------+-------+')
    print('     | ', end='') #print the start of each new line
  
    for offset in range(0, len(temp)):
        print(' ' * (5 - len(str(temp[offset]))) + str(temp[offset]) + ' | ', end='')
        
        if((offset+1)%9 == 0):
            print('\n     +-------+-------+-------+-------+-------+-------+-------+-------+-------+')
            if(offset != len(temp)-1):
                print('     | ', end='')
    print('\n')
     
##############################################################################################################
# Check parameter boundaries, build the port list
##############################################################################################################        
def buildPortList(pingOnly, portDepth, firstPort, lastPort, portFile, fileType):
    pts = []        #the ports to be checked
    temp = []       #list to temporarily hold the ports
    cont = '0'
    
    if pingOnly == False:           #if we're only doing a ping sweep we'll skip building a port list (-p overrides port selection)
        if portFile == None:        #if we're loading ports from a file, skip defaults (-a/-b overrides default selections)
            if portDepth == '1000': #if the port depth spec is set to 1000 load the nmap default 1000 ports
                print('[+]Testing with the Nmap top 1000 ports')
                pts = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389]
            if portDepth == 'fast': #if we're doing a quicker scan we'll go with the nmap default 11
                pts = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]
                print('[+]Testing with the 11 default Nmap ports')
            if portDepth == None:   #if the port depth was not specified default to the nmap default 11
                print('[+]Testing with the 11 default Nmap ports')
                pts = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]
        else:
            if fileType == 'c': #if the port file was specified and the file type is CSV (-a)
                try:            
                    f = open(portFile, 'r')     #open the file readl-only    
                    temp = f.read().split(',')  #load the ports separated by commas
                    for x in range(0, len(temp)):                               #for each one check if it's:
                        if temp[x].strip().isdigit():                           #1) a number and 
                            if (int(temp[x]) > 0) and (int(temp[x]) < 65535):   #2) a valid port number
                                pts.append(temp[x].strip())                #if it passes those checks add it to the list
                    if(len(pts)==0):
                        print('[!] ' + portFile + ' is empty. Quitting.')
                        quit()
                    print('The ports to be tested from the input file are:')
                    print(pts)
                    cont = input('Press 0 (zero) to quit, anything else to continue : ')
                    if cont == '0':
                        quit()
                    f.close()                                                   #close the file
                except OSError:
                    print("Could not open/read file:", portFile)                #if an error ocurred
            if fileType == 'n':                                                 # if the port file is a text file with one port per line
                try:
                    with open(portFile) as file:    
                        while line := file.readline():                          #read each line, check if it's:
                            if line.strip().isdigit():                          #1) a number and
                                if (int(line.strip()) > 0) and (int(line.strip()) < 65535): #2) a valid port number
                                    pts.append(int(line.strip()))               #strip off any spaces
                    if(len(pts)==0):
                        print('[!] ' + portFile + ' is empty. Quitting.')
                        quit()
                    print('The ports to be tested from the input file are:')
                    printPortList(pts)
                    cont = input('Press 0 (zero) to quit, anything else to continue : ')
                    if cont == '0':
                        quit()
                except OSError:
                    print("Could not open/read file:", portFile)
    return pts      #return the port list

##############################################################################################################
# Do a ping sweep
##############################################################################################################
def pingSweep(sub, nodes, ipFreeList, ipFoundList):
    print("\n[+]Starting ping sweep\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        future_to_ping = {executor.submit(pingHost, (sub+str(node)), ipFreeList, ipFoundList): node for node in nodes}
        for future in concurrent.futures.as_completed(future_to_ping):
            node = future_to_ping[future]
            try:
                data = future.result()
            except Exception as e:
                print('%s generated an exception: %s' % (node, e))
    print("[+]Ping sweep complete\n")

##############################################################################################################
# Test all tcp ports
##############################################################################################################
def tcpSweep(ipFreeList, index, portFreeList, portFoundList):
    start = time.time()
    print('\nDoing full scan on ' + ipFreeList[int(index)-1])
    portsToScan = range(1,65535)
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        future_to_port = {executor.submit(scanPort, ipFreeList[int(index)-1], portToScan, ipFreeList, portFound): portToScan for portToScan in portsToScan}
        for future in concurrent.futures.as_completed(future_to_port):
            portToScan = future_to_port[future]
            try:
                data = future.result()
            except Exception as e:
                print('%s generated an exception: %s' % (host, e))
                
    end = time.time()
    
    print('Time taken in seconds : ', end - start)
    
    if(len(portFound)==0):
        print('\n\n[+]No open ports found')
    else:
        print('[!!!]Got a reply on ' + str(len(portFound)) + ', try another IP[!!!]')
            
##############################################################################################################
# Pings the host with one ICMP packet, if the text "Lost = 0" is present, the IP is added to the found list
# otherwise it's added to the free list
##############################################################################################################
def pingHost(ipAddx, pingFree, pingFound):
    output = subprocess.run(["ping", "-n", "1", "-w", "100", ipAddx], stdout=subprocess.PIPE) 
    if str(output).find("Lost = 0") >= 0:
        pingFound.append(ipAddx)
    else:
        pingFree.append(ipAddx)
        
##################################################
# Scan ports in a list using multiple threads
##################################################
def scanPorts(ip, ports, tcpFree, tcpFound):
    threads = []
    
    for port in ports:
        thread = threading.Thread(target=scanPort, args=(ip, port, tcpFound, tcpFree))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
        
##################################################
# Function to scan a single port
##################################################
def scanPort(ip, port, tcpFound, tcpFree):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            if ip not in tcpFound:  #don't add an IP that's already been added
                tcpFound.append(ip) #if it's the first detection add it
            if ip in tcpFree:
                tcpFree.remove(ip)
        sock.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

##################################################
# Function print a table of free IPs
##################################################
def freePrint(ipPrint, title):
    rows = math.floor(len(ipPrint)/3)
    leftOvers = len(ipPrint)%3
    offset = 0

    if title == 0:
        midTitle = '     |                     Potentially Free IP Addresses                     |'
        print("[+]Here are the IPs that did NOT respond to me:")
    else:
        midTitle = '     |                           Found IP Addresses                          |'
        print("[+]Here are the IPs that responded to me:")
        
    print('     +-----------------------+-----------------------+-----------------------+')
    print(midTitle)
    print('     +-----------------------+-----------------------+-----------------------+')

    if (len(ipPrint) == 0):
        print('     |                        No Response From Any IP                        |')
        print('     +-----------------------+-----------------------+-----------------------+')

    if (len(ipPrint) > 3):
        for x in range(1,rows+1):
            print('     | ' + ' ' * (3 - len(str(offset + 1))) + str(offset + 1) + ' - ' + ipPrint[offset] + ' ' * (15 - len(ipPrint[offset])) + ' | ' + ' ' * (3 - len(str(offset + 2))) + str(offset + 2) + ' - ' + ipPrint[offset+1] + ' ' * (15 - len(ipPrint[offset+1])) + ' | ' +	' ' * (3 - len(str(offset + 3))) + str(offset + 3) + ' - ' + ipPrint[offset+2] + ' ' * (15 - len(ipPrint[offset+2])) + ' |' )
            print('     +-----------------------+-----------------------+-----------------------+')
            offset+=3
    
    if (leftOvers == 1):
        print('     | ' + ' ' * (3 - len(str(offset + 1))) + str(offset + 1) + ' - ' + ipPrint[offset] + ' ' * (15 - len(ipPrint[offset])) + ' |' + ' ' * 22 + ' |' + ' ' * 22 + ' |')
        print("     +-----------------------+-----------------------+-----------------------+")

    if (leftOvers == 2):
        print('     | ' + ' ' * (3 - len(str(offset + 1))) + str(offset + 1) + ' - ' + ipPrint[offset] + ' ' * (15 - len(ipPrint[offset])) + ' | ' + ' ' * (3 - len(str(offset + 2))) + str(offset + 2) + ' - ' + ipPrint[offset+1] + ' ' * (15 - len(ipPrint[offset+1])) + ' |' + ' ' * 22 + ' |' )
        print("     +-----------------------+-----------------------+-----------------------+")

    if (len(ipPrint) == 3):
        print('     - ' + ' ' * (3 - len(str(offset + 1))) + str(offset + 1) + ' - ' + ipPrint[offset] + ' ' * (15 - len(ipPrint[offset])) + ' | ' + ' ' * (3 - len(str(offset + 2))) + str(offset + 2) + ' - ' + ipPrint[offset+1] + ' ' * (15 - len(ipPrint[offset+1])) + ' | ' +	' ' * (3 - len(str(offset + 3))) + str(offset + 3) + ' - ' + ipPrint[offset+2] + ' ' * (15 - len(ipPrint[offset+2])) + ' |' )
        print("     +-----------------------+-----------------------+-----------------------+")
    print(' ')

##############################################################################################################
# Ask if the user wants a full port scan
##############################################################################################################
def pickListDoFullScan(maxVal):
    print('\n\nIf you want to do a full scan of all 65535 ports for, you can')
    print('select an index for that scan. It may take several minutes.')
    
    compIndex = ''
    goodInput = False
    
    while(goodInput==False):
        compIndex = input('\n[+]Enter the index to the left of the IP or 0 to quit: ')

        if(compIndex.isdigit()==False):
            print('\n[!]Value must be a digit between 1 and ' + str(maxVal) + ', or 0 to quit\n')
        else:
            if (int(compIndex) < 0 or int(compIndex) > maxVal):
                print('\n[!]Value is out of range, must between 1 and ' + str(maxVal) + ', or 0 to quit\n')

            if((int(compIndex) <= maxVal) and (int(compIndex) >= 0)):
                goodInput = True
            
    return compIndex
    
##############################################################################################################
# Entry point
##############################################################################################################
if __name__ == "__main__":
#init and declare the variables we'll be using
    start = time.time()     #for checking the amount of time a scan takes
    subnet = args['s']      #the first three octets of an address separated with dots (1.2.3)
    first = int(args['f'])  #the first host octet to start with
    last = int(args['l'])   #the last host octet to end with
    csvFile = args['a']     #CSV port input file
    newline = args['b']     #newline port input file
    ipFound = []            #for recording found IPs
    ipFree = []             #for recording potentially free IPs
    portsToScan = []        #the list of ports to scan
    compIndexFullScan = ''  #list index of the IP to do a full scan on
    portFound = []          #ips where the host was found by tcp connection
    portFree = []           #ips where the host was not found by tcp connection
    portFile = ''           #when a user uses a file with a list of ports
    fileType = ''           #c = csv, n = ports are listed one per line

    #Part 1 - do the tasks that are one-time tasks first
    printHeader()                   #print a short header
    parmChecks(first, last, subnet, csvFile, newline) #check the input parameters, ensure they're all in bounds
    hosts = range(first,last+1)     #build the range of hosts in the host octet
    if(csvFile != None):            #if the csv parameter was not present
        portFile = csvFile
        fileType = 'c'
    if(newline != None):
        portFile = newline
        fileType = 'n'
    if(newline == None and csvFile == None):
        portFile = None
    subnet+='.'                     #add the last dot to the subnet for building IP addresses
    portsToScan = buildPortList(args['p'], args['g'], first, last, portFile, fileType) #build port list with args

    #Part 2 - see if we can quickly
    #weed out hosts that reply to a ping sweep
    pingSweep(subnet, hosts, ipFree, ipFound)

    #if the -p switch was given on the command line the ping sweep is all that's we're doing to find live hosts
    #skip the TCP connection scan, otherwise call the scan ports function with the IPs to check
    if args['p'] == False:
        print("[+]Checking " + str(len(ipFree)) + " hosts that did not respond to ICMP requests\n")
        for ipAdx in ipFree:
            scanPorts(ipAdx, portsToScan, ipFree, ipFound)

    #print results for both a list of IPs that were found to be live and the ones that did not respond to
    #ICMP requests or TCP connections
    freePrint(ipFound, 1)
    freePrint(ipFree, 0)

    #print the time it took to do everything so far
    end = time.time()
    print('Time taken in seconds : ', end - start)

    # TODO: add while loop to allow the user to deep scan multiple hosts
    #       one at a time until the user exits

    #do a deep scan if the user wants, ask the user and return the value of the index
    #if it's zero, the program exits, otherwise call for the full scan
    compIndexFullScan = pickListDoFullScan(len(ipFree))
    if (int(compIndexFullScan)==0):
        print('\n\nGoodbye\n\n')
        exit
    else:
        tcpSweep(ipFree, compIndexFullScan, portFree, portFound) 
