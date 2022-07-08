# pingnet
## Multi-threaded script to ping network address(CIDR), IP address, hostname

## Install

`pip install pingnet`
## Usage
```sh
usage: pingnet [-h] [-f [FILE]] [-n [COUNT]] [-w] [address]

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
```

## Example
```sh
shell> pingnet 8.8.8.8/30 -n 1 
Ping count: 1

Hostname/IP Address                                          Average Round Trip Times
-------------------------------------------------------------------------------------
IP: 8.8.8.8                                                  Average RTT: 20ms
-------------------------------------------------------------------------------------
Test completed! (It took 3.93 seconds to test 4 addresses.)

Reachable:
 8.8.8.8
Not reachable:
 8.8.8.11, 8.8.8.10, 8.8.8.9
Unknown host:

```

Returns RTT value on reachable addresses.

Create hosts.txt with address on each line

hosts.txt Example:

8.8.8.8
1.1.1.1
google.com
8.8.8.8/24
kevinjin.com



Outputs results in txt format. 
