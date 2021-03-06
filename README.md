# pingNet
pingNet is a multi-threaded Python tool designed to ping one or multiple IP addresses on a subnet (CIDR) at the same time. You can also ping every IP address range and hostname in a text file.

## Installation

To install:

`$ pip install pingnet`

To upgrade:

`$ pip install --upgrade pingnet`
## Usage
```sh
$ pingnet
usage: pingnet [-h] [-f [FILE]] [-n [COUNT]] [-w] [-V] [address]

positional arguments:
  address               CIDR/hostname/IP
                        Example:
                            pingnet 192.168.1.0/24
                            pingnet www.google.com
                            pingnet 8.8.8.8

options:
  -h, --help            show this help message and exit
  -f [FILE], --file [FILE]
                        specify text file that stores CIDR/hostname/IP
  -n [COUNT], --count [COUNT]
                        number of echo requests to send, default 3
  -w, --write           write results to txt files
  -V, --version         show program's version number and exit
```

## Example

#### Ping a single subnet range/IP/hostname: 
Add `-n` argument to set number of ICMP requests, default is 3
```sh
$ pingnet 8.8.8.8/30 -n 1 

                                  PingNet [v0.3.2]
Number of ping requests: 1                                        2022/07/15 11:23:57
IP/Host                                                     Min        Max        Avg
-------------------------------------------------------------------------------------
IP: 8.8.8.8                                                20ms       20ms       20ms
-------------------------------------------------------------------------------------
Number of total addresses: 4                            Time elapsed:    3.99 seconds

Alive: [1]
 8.8.8.8
Dead: [3]
 8.8.8.9, 8.8.8.10, 8.8.8.11
Unknown: [0]

```

#### ping every CIDR block/IP/hostname in a text file: 


Example `hosts.txt` file containing mix of CIDRs/IPs/hostnames, along with some invalid addresses. PingNet will ignore empty lines and lines start with `#`, also you can comment each line with # followed by the address. 
```txt
192.168.13.0/24
kevinjin.com        #myblog
1.1.1.1             #Cloudflare DNS
invalid.address
google.com
#8.8.4.4
8.8.8.8/30
```

Run the script with `-f` argument to specify the `hosts.txt` file. 

```sh
$ pingnet -f hosts.txt -n 2   

                                  PingNet [v0.3.4]
Number of ping requests: 2                                        2022/07/18 12:53:20
IP/Host                                                     Min        Max        Avg
-------------------------------------------------------------------------------------
IP: 192.168.13.1                                            0ms        0ms        0ms
IP: 192.168.13.128                                          0ms        0ms        0ms
IP: 1.1.1.1                                                13ms       14ms       13ms
IP: 8.8.8.8                                                19ms       42ms       30ms
Host: google.com [172.217.14.206]                          20ms       41ms       30ms
Host: kevinjin.com [185.199.110.153]                       14ms       18ms       16ms
-------------------------------------------------------------------------------------
Number of total addresses: 264                          Time elapsed:    9.18 seconds

Alive: [6]
 1.1.1.1, 8.8.8.8, 192.168.13.1, 192.168.13.128, google.com, kevinjin.com
Dead: [257]
 8.8.8.9, 8.8.8.10, 8.8.8.11, 192.168.13.0, 192.168.13.2, 192.168.13.3, 192.168.13.4, 192.168.13.5, 192.168.13.6, 192.168.13.7, 192.168.13.8, 192.168.13.9, 192.168.13.10, 192.168.13.11, 192.168.13.12, 192.168.13.13, 192.168.13.14, 192.168.13.15, 192.168.13.16, 192.168.13.17, 192.168.13.18, 192.168.13.19, 192.168.13.20, 192.168.13.21, 192.168.13.22, 192.168.13.23, 192.168.13.24, 192.168.13.25, 192.168.13.26, 192.168.13.27, 192.168.13.28, 192.168.13.29, 192.168.13.30, 192.168.13.31, 192.168.13.32, 192.168.13.33, 192.168.13.34, 192.168.13.35, 192.168.13.36, 192.168.13.37, 192.168.13.38, 192.168.13.39, 192.168.13.40, 192.168.13.41, 192.168.13.42, 192.168.13.43, 192.168.13.44, 192.168.13.45, 192.168.13.46, 192.168.13.47, 192.168.13.48, 192.168.13.49, 192.168.13.50, 192.168.13.51, 192.168.13.52, 192.168.13.53, 192.168.13.54, 192.168.13.55, 192.168.13.56, 192.168.13.57, 192.168.13.58, 192.168.13.59, 192.168.13.60, 192.168.13.61, 192.168.13.62, 192.168.13.63, 192.168.13.64, 192.168.13.65, 192.168.13.66, 192.168.13.67, 192.168.13.68, 192.168.13.69, 192.168.13.70, 192.168.13.71, 192.168.13.72, 192.168.13.73, 192.168.13.74, 192.168.13.75, 192.168.13.76, 192.168.13.77, 192.168.13.78, 192.168.13.79, 192.168.13.80, 192.168.13.81, 192.168.13.82, 192.168.13.83, 192.168.13.84, 192.168.13.85, 192.168.13.86, 192.168.13.87, 192.168.13.88, 192.168.13.89, 192.168.13.90, 192.168.13.91, 192.168.13.92, 192.168.13.93, 192.168.13.94, 192.168.13.95, 192.168.13.96, 192.168.13.97, 192.168.13.98, 192.168.13.99, 192.168.13.100, 192.168.13.101, 192.168.13.102, 192.168.13.103, 192.168.13.104, 192.168.13.105, 192.168.13.106, 192.168.13.107, 192.168.13.108, 192.168.13.109, 192.168.13.110, 192.168.13.111, 192.168.13.112, 192.168.13.113, 192.168.13.114, 192.168.13.115, 192.168.13.116, 192.168.13.117, 192.168.13.118, 192.168.13.119, 192.168.13.120, 192.168.13.121, 192.168.13.122, 192.168.13.123, 192.168.13.124, 192.168.13.125, 192.168.13.126, 192.168.13.127, 192.168.13.129, 192.168.13.130, 192.168.13.131, 192.168.13.132, 192.168.13.133, 192.168.13.134, 192.168.13.135, 192.168.13.136, 192.168.13.137, 192.168.13.138, 192.168.13.139, 192.168.13.140, 192.168.13.141, 192.168.13.142, 192.168.13.143, 192.168.13.144, 192.168.13.145, 192.168.13.146, 192.168.13.147, 192.168.13.148, 192.168.13.149, 192.168.13.150, 192.168.13.151, 192.168.13.152, 192.168.13.153, 192.168.13.154, 192.168.13.155, 192.168.13.156, 192.168.13.157, 192.168.13.158, 192.168.13.159, 192.168.13.160, 192.168.13.161, 192.168.13.162, 192.168.13.163, 192.168.13.164, 192.168.13.165, 192.168.13.166, 192.168.13.167, 192.168.13.168, 192.168.13.169, 192.168.13.170, 192.168.13.171, 192.168.13.172, 192.168.13.173, 192.168.13.174, 192.168.13.175, 192.168.13.176, 192.168.13.177, 192.168.13.178, 192.168.13.179, 192.168.13.180, 192.168.13.181, 192.168.13.182, 192.168.13.183, 192.168.13.184, 192.168.13.185, 192.168.13.186, 192.168.13.187, 192.168.13.188, 192.168.13.189, 192.168.13.190, 192.168.13.191, 192.168.13.192, 192.168.13.193, 192.168.13.194, 192.168.13.195, 192.168.13.196, 192.168.13.197, 192.168.13.198, 192.168.13.199, 192.168.13.200, 192.168.13.201, 192.168.13.202, 192.168.13.203, 192.168.13.204, 192.168.13.205, 192.168.13.206, 192.168.13.207, 192.168.13.208, 192.168.13.209, 192.168.13.210, 192.168.13.211, 192.168.13.212, 192.168.13.213, 192.168.13.214, 192.168.13.215, 192.168.13.216, 192.168.13.217, 192.168.13.218, 192.168.13.219, 192.168.13.220, 192.168.13.221, 192.168.13.222, 192.168.13.223, 192.168.13.224, 192.168.13.225, 192.168.13.226, 192.168.13.227, 192.168.13.228, 192.168.13.229, 192.168.13.230, 192.168.13.231, 192.168.13.232, 192.168.13.233, 192.168.13.234, 192.168.13.235, 192.168.13.236, 192.168.13.237, 192.168.13.238, 192.168.13.239, 192.168.13.240, 192.168.13.241, 192.168.13.242, 192.168.13.243, 192.168.13.244, 192.168.13.245, 192.168.13.246, 192.168.13.247, 192.168.13.248, 192.168.13.249, 192.168.13.250, 192.168.13.251, 192.168.13.252, 192.168.13.253, 192.168.13.254, 192.168.13.255
Unknown: [1]
 invalid.address

```
`-w` argument exports three txt files storing results.
```
2022-07-18-Alive.txt
2022-07-18-Alive_RTT.txt
2022-07-18-Dead.txt
```