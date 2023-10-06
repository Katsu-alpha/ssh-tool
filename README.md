# ssh-tool

A go tool to connect to multiple network devices and send commands.

### How to use

Create a text file with list of commands in it and save it as 'commands.txt'

Run ssh-tool with the IP addresses of target devices in the command line parameters.

```
ssh-tool 192.168.1.100
```

You can speficy range of IP address by '-'

```
ssh-tool 192.168.1.100-105
```

### Options

- `-p <password>` : Specify admin password
- `-c <filename>` : Specify command file
- `-d <seconds>` : Specify duration
- `-iap` : Use this if the target device is Instant AP
- `-debug` : Enable debug output

### Commands file syntax

You can list the commands as below. Ssh-tool will run each command only once in order.
```
show version
show clock
no paging
show running-conf
```

You can specify the interval before each command to run the command repeatedly.
You can also specify the number of iteration.
```
30,show user  => run every 30 seconds, indefinitely
1m,show datapath session   => run every 1 minutes, indefinitely
10;5,show clock   => run every 10 seconds, 5 times only
```

You can use NAME=VAR. You can use `:upper` or `:lower` decorator.
```
MAC=00:11:22:aa:bb:cc
30,show log all | include $MAC,${MAC:upper}
30,show ap debug client-stats client-mac $MAC
```
