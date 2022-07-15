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

version = "0.3.1"
reachable = []                              #Empty list to collect reachable hosts
reachable_avg = []                          #Empty list to collect reachable hosts + RTT
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
        pattern_all = r"Minimum = (\d+\S+), Maximum = (\d+\S+), Average = (\d+\S+)"
        keyword = "Average"
        ping_test = subprocess.Popen(["ping", "-n", ping_count, ip], stdout = subprocess.PIPE,stderr = subprocess.PIPE)
    elif "darwin" in platform:                 #Linux & Mac
        pattern = r"= \d+\.\d+/(\d+\.\d+)/\d+\.\d+/\d+\.\d+ ms"
        pattern_all = r"= (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/\d+\.\d+ ms"
        pattern_ip = r"\(\d+.\d+.\d+.\d+\)"
        keyword = "avg"
        ping_test = subprocess.Popen(["ping", "-t 4","-c", ping_count, ip], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    else:
        pattern = r"= \d+\.\d+/(\d+\.\d+)/\d+\.\d+/\d+\.\d+ ms"
        pattern_all = r"= (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/\d+\.\d+ ms"
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
        avg = re.findall(pattern, output.decode())[0]   #Regex to find latency
        rtt = re.findall(pattern_all, output.decode())[0]
        
        if "linux" in platform or "darwin" in platform:                 
            rtt_i = [0, 2, 1]
            rtt = [rtt[i]+"ms" for i in rtt_i]               #reorder to min/max/avg for linux&mac
            avg = avg+"ms"
        if type == "ip":
            print("IP: {0:49} {1:>9}  {2:>9}  {3:>9}".format(ip, rtt[0],rtt[1],rtt[2]))
        else:                                   
            ipadd = re.findall(pattern_ip,output.decode())[0]       #if type is hostname, add resolved IP address
            print("Host: {0:47} {1:>9}  {2:>9}  {3:>9}".format(ip+" "+ipadd,rtt[0],rtt[1],rtt[2]))
        reachable.append(ip)
        reachable_avg.append("{0:41} RTT:{1}".format(ip, avg))
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
    parser.add_argument("-V", "--version", action="version", version="%(prog)s "+version)
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    ping_count = args.count if args.count else "3" 
    print("\n"+" "*34+"PingNet ["+version+"]")
    if "darwin" in platform:            #set "ulimit -n" higher for Mac, to avoid "OSError: [Errno 24] Too many open files"
        target_procs=50000
        cur_proc, max_proc=resource.getrlimit(resource.RLIMIT_NOFILE)
        target_proc = min(max_proc,target_procs)
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(cur_proc,target_proc),max_proc))
    date = datetime.date.today()
    now = datetime.datetime.now()
    
    print("Ping count: {0:54}{1}".format(ping_count,now.strftime("%Y/%m/%d %H:%M:%S")),end="")
    start_time = time.time()                 
    print("\nIP/Host {0:51} Min        Max        Avg {1}".format("",""))
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
            for item in reachable_avg:
                f.write("%s\n" % item)
        with open('%s-Not_reachable.txt' % date, 'w') as f:
            for item in not_reachable_sorted:
                f.write("%s\n" % item)
        print("\nCheck txt files for complete results!")

if __name__ == "__main__":
    main()
