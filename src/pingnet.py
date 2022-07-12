import argparse
import textwrap
import ipaddress
import subprocess
import datetime
import time
import re
import sys
from ipaddress import ip_address
from sys import platform
from threading import Thread
if "darwin" in platform:
     import resource # pylint: disable=import-error

reachable = []                              #Empty list to collect reachable hosts
reachable_rtt = []                          #Empty list to collect reachable hosts + RTT
not_reachable = []                          #Empty list to collect unreachable hosts
unknown_host = []                           #Empty list to collect Unknown hosts

def ipsorter(s):
    try:
        ip = int(ip_address(s))
    except ValueError:
        return (1, s)
    return (0, ip)

def ping_test (ip,ping_count):  
    if "win32" in platform:                   #platform equals win32 for Windows, equals linux for Linux, darwin for Mac
        pattern = r"Average = (\d+\S+)"
        pattern_ip = r"\[\d+.\d+.\d+.\d+\]"
        keyword = "Average"
        ping_test = subprocess.Popen(["ping", "-n", ping_count, ip], stdout = subprocess.PIPE,stderr = subprocess.PIPE)
    elif "darwin" in platform:                 #Linux & Mac
        pattern = r"= \d+\.\d+/(\d+\.\d+)/\d+\.\d+/\d+\.\d+ ms"
        pattern_ip = r"\(\d+.\d+.\d+.\d+\)"
        keyword = "avg"
        ping_test = subprocess.Popen(["ping", "-t 4","-c", ping_count, ip], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    else:
        pattern = r"= \d+\.\d+/(\d+\.\d+)/\d+\.\d+/\d+\.\d+ ms"
        pattern_ip = r"\(\d+.\d+.\d+.\d+\)"
        keyword = "avg"
        ping_test = subprocess.Popen(["ping", "-W 4","-c", ping_count, ip], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    output = ping_test.communicate()[0]
    output_str = str(output)

    if keyword in output_str:                #If Average latency is available, it's reachable
        try:
            ipaddress.ip_address(ip)           #Check if it's an IP address
            type = "ip"
        except ValueError:                      
            type = "hostname"
        rtt = re.findall(pattern, output.decode())[0]   #Regex to find latency
        if "linux" in platform or "darwin" in platform:                 
            rtt = rtt+"ms"
        if type == "ip":
            print("IP: {0:56} Average RTT: {1}".format(ip, rtt))
        else:                                   
            ipadd = re.findall(pattern_ip,output.decode())[0]       #if type is hostname, add resolved IP address
            print("Hostname: {0:50} Average RTT: {1}".format(ip+" "+ipadd,rtt))
        reachable.append(ip)
        reachable_rtt.append("{0:41} RTT:{1}".format(ip, rtt))
    elif "could not find host" in output_str or "nknown host" in output_str or "not known" in output_str:
        unknown_host.append(ip)
    else:
        not_reachable.append(ip)            #Else, it's not reachable

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", nargs="?", action="store", help="specify text file that stores CIDR/hostname/IP")
    group.add_argument("address", nargs="?", default=[], help= textwrap.dedent('''CIDR/hostname/IP
Example:
    pingnet 192.168.1.0/24
    pingnet www.google.com
    pingnet 8.8.8.8 '''))
    parser.add_argument("-n", "--count", nargs="?", action="store", help="number of echo requests to send, default 3")
    parser.add_argument("-w", "--write", action="store_true", help="write results to txt files")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s 0.2.6")
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.count:                      #if there's -n argument, set count 
        ping_count=args.count[0]
        print("Ping count: " + ping_count)
    else:
        ping_count="3"                  #default ping count is set to 3
        print("Default ping count: 3")
    
    if "darwin" in platform:            #set "ulimit -n" higher for Mac, to avoid "OSError: [Errno 24] Too many open files"
        target_procs=50000
        cur_proc, max_proc=resource.getrlimit(resource.RLIMIT_NOFILE)
        target_proc = min(max_proc,target_procs)
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(cur_proc,target_proc),max_proc))
    date = datetime.date.today()
    start_time = time.time()                 
    print("\nHostname/IP Address {0:40} Average Round Trip Times {1}".format("",""))
    print("-------------------------------------------------------------------------------------")
    thread_list = []                        
    count = 0                              #total address count

    if args.file:                             #if argument -f is specified
        f = open(args.file,'r')               #open file
        for line in f:
            if line != "\n":
                IP = line.strip()
                if "/" in IP:                     #If Address has subnet mask symbol(/), eg: 192.168.1.0/30
                    for ip in ipaddress.IPv4Network(IP,False): 
                        count += 1
                        th = Thread(target=ping_test, args=(str(ip),ping_count,))  
                        th.start()
                        thread_list.append(th)
                else:                             #Single IP address or hostname, instead of IP range
                    count += 1
                    th = Thread(target=ping_test, args=(IP,ping_count,))   #args should be tuple, need extra comma when passing only 1 param
                    th.start()
                    thread_list.append(th)

    if args.address:
        if "/" in args.address:                     #If Address has subnet mask symbol(/), eg: 192.168.1.0/30
            if ipaddress.ip_network(args.address):  #validate if it's a CIDR network
                for ip in ipaddress.IPv4Network(args.address,False): 
                    count += 1
                    th = Thread(target=ping_test, args=(str(ip),ping_count,))  
                    th.start()
                    thread_list.append(th)
        else:                             #Single IP address or hostname, instead of IP range
            count += 1
            ping_test(args.address,ping_count)
            '''
            th = Thread(target=ping_test, args=(args.address,ping_count,))   #args should be tuple, need extra comma when passing only 1 param
            th.start()
            thread_list.append(th)
            '''
    for th in thread_list:
        th.join()
    time_elapsed = time.time() - start_time            #calculate elapsed time
    print("-------------------------------------------------------------------------------------")
    print("Test completed! (It took %.2f seconds to test %d addresses.)\n" % (time_elapsed,count))
    reachable_sorted = sorted(reachable, key=ipsorter)
    print("Reachable:\n {} ".format((", ").join(reachable_sorted)))
    not_reachable_sorted = sorted(not_reachable, key=ipsorter)
    print("Not reachable:\n {}".format((", ").join(not_reachable_sorted)))
    unknown_host_sorted = sorted(unknown_host, key=ipsorter)
    print("Unknown host:\n {}".format((", ").join(unknown_host_sorted)))
    
    if args.write:                      #-w argument, export output as txt
        with open('%s-Reachable.txt' % date, 'w') as f:
            for item in reachable_sorted:
                f.write("%s\n" % item)
        with open('%s-Reachable_RTT.txt' % date, 'w') as f:
            for item in reachable_rtt:
                f.write("%s\n" % item)
        with open('%s-Not_reachable.txt' % date, 'w') as f:
            for item in not_reachable_sorted:
                f.write("%s\n" % item)
        print("\nCheck txt files for complete results!")

if __name__ == "__main__":
    main()