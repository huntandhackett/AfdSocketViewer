# AfdSocketView

**AfdSocketView** is a command-line tool for inspecting properties of *Ancillary Function Driver* (AFD) socket handles. The tool queries information from `AFD.sys` - a low-level Windows component that powers networking sockets commonly used via the [Winsock library](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2). Similar functionality (but in GUI) is also available in [System Informer](https://systeminformer.io/). To learn how it all works, check our **blog post**: [Improving AFD Socket Visibility for Windows Forensics & Troubleshooting](https://www.huntandhackett.com/blog/improving_afd_socket_visibility).

## Usage

```
AfdSocketView - a tool for inspecting AFD socket handles by Hunt & Hackett.

Usage: AfdSocketView [-p [*|PID|Image name]] [-h [Handle value]] [-v]
   -p: selects which process(es) to inspect
   -h: show all properties for a specific handle
   -v: enable verbose output mode

Examples:
  AfdSocketView -p *
  AfdSocketView -p chrome.exe
  AfdSocketView -p 4812 -h 0x2c8 -v
```

The tool can operate in **two modes**: 
1. Enumerating socket handles used by the given processes. 
2. Inspecting details about a specific socket handle.

When enumerating handles, the tool will display handle values and their summary. You can specify the process ID, the image name, or a wildcard pattern to filter which processes to inspect:

```
P:\>AfdSocketView.exe -p "Network Stuff.exe"
AfdSocketView - a tool for inspecting AFD socket handles by Hunt & Hackett.

Network Stuff.exe [7620]
[0x0624] AFD socket: Bound TCP on 127.0.0.1:8000
[0x0640] AFD socket: Connected TCP on 127.0.0.1:54368 to 127.0.0.1:8000
[0x0660] AFD socket: Connected TCP on 127.0.0.1:8000
[0x06C8] AFD socket: Bound UDP on 0.0.0.0:8000
[0x070C] AFD socket: Open UDP
[0x075C] AFD socket: Bound ICMP on 0.0.0.0

Complete.
```

If you specify a handle value using the `-h` parameter, the tool proceeds to dump all available information about the socket:

```
P:\>AfdSocketView.exe -p 7620 -h 0x640
AfdSocketView - a tool for inspecting AFD socket handles by Hunt & Hackett.

Handle 0x0640 of Network Stuff.exe [7620]:
[----- Winsock context -----]
State                       : Connected
Address family              : Internet
Socket type                 : Stream
Protocol                    : TCP
Local address length        : 16 bytes
Remote address length       : 16 bytes
Linger                      : False
Linger timeout              : None
Send timeout                : None
Receive timeout             : None
Receive buffer size         : 64 KiB
Send buffer size            : 64 KiB
Flags                       : 0x1000
 - Listening                : False
 - Broadcast                : False
 - Debug                    : False
 - OOB in line              : False
 - Reuse addresses          : False
 - Exclusive address use    : False
 - Non-blocking             : False
 - Don't use wildcard       : False
 - Receive shutdown         : False
 - Send shutdown            : False
 - Conditional accept       : False
 - SAN                      : False
 - TLI                      : True
 - RIO                      : False
 - Receive suffer size set  : False
 - Send suffer size set     : False
Creation flags              : 0x1
 - Overlapped               : True
 - Multipoint control root  : False
 - Multipoint control leaf  : False
 - Multipoint data root     : False
 - Multipoint data leaf     : False
 - Access SACL              : False
 - No handle inherit        : False
 - Registered I/O           : False
Catalog entry ID            : 1001
Service flags               : 0x20066
 - Connectionless           : False
 - Guaranteed delivery      : True
 - Guaranteed order         : True
 - Message-oriented         : False
 - Pseudo-stream            : False
 - Graceful close           : True
 - Expedited data           : True
 - Connect data             : False
 - Disconnect data          : False
 - Broadcast                : False
 - Support multipoint       : False
 - Multipoint control plane : False
 - Multipoint data plane    : False
 - QoS supported            : False
 - Interrupt                : False
 - Unidirectional send      : False
 - Unidirectional receive   : False
 - IFS handles              : True
 - Partial message          : False
 - SAN support SDP          : False
Provider flags              : 0x8
 - Multiple entries         : False
 - Recommended entry        : False
 - Hidden                   : False
 - Matches protocol zero    : True
 - Network direct           : False
Group ID                    : 0
Group type                  : Neither
Group priority              : 0
Last error                  : 0
Async select HWND           : 0x0
Async select serial number  : 0
Async select message        : 0
Async select event          : 0
Disabled async select events: 0
Provider ID                 : {E70F1AA0-AB8B-11CF-8CA3-00805F48A192}

[-------- Addresses --------]
Local address               : 127.0.0.1:54368
Remote address              : 127.0.0.1:8000

[---- AFD info classes -----]
Maximum send size           : 3.99 GiB
Pending sends               : 0
Maximum path send size      : 3.99 GiB
Receive window size         : 64 KiB
Send window size            : 64 KiB
Connect time                : 24 min 6 sec ago (2025-04-15 11:17:37)
Group ID                    : 0
Group type                  : Neither

[------- TDI devices -------]
TDI address device          : N/A (transport is not TDI)
TDI connection device       : N/A (transport is not TDI)

[--- Socket-level options --]
Reuse address               : False
Keep alive                  : False
Don't route                 : False
Broadcast                   :
OOB in line                 : False
Receive buffer size         : 2.49 MiB
Maximum message size        : 3.99 GiB
Conditional accept          : False
Pause accept                : False
Compartment ID              : 1
Randomize port              : False
Port scalability            : False
Reuse unicast port          : False
Exclusive address use       : False

[----- IP-level options ----]
Header included             :
Type-of-service             : 0
Unicast TTL                 : 128
Multicast interface         :
Multicast TTL               :
Multicast loopback          :
Don't fragment              : True
Receive packet info         :
Receive TTL                 :
Broadcast reception         :
IPv6 protection level       : Unrestricted
Receive arrival interface   :
Receive dest. address       :
IPv6-only                   : True
Interface list              : False
Unicast interface           : Default
Receive routing header      :
Receive type-of-service     :
Original arrival interface  :
Receive ECN                 :
Recveive ext. packet info   :
WFP redirect records        :
WFP redirect context        :
MTU discovery               : Not set
Path MTU                    : 65535
Receive ICMP errors         :
Upper MTU bound             : -1

[---- TCP-level options ----]
No delay                    : False
Expedited data              : False
Keep alive                  : 2 hours
Maximum segment size        : 63.9 KiB
Retry timeout               : None
URG interpretation          : False
No URG                      : False
At mark                     : False
No SYN retries              : False
Timestamps                  : False
Congestion algorithm        : 5
Delay FIN ACK               : False
Retry timeout (precise)     : None
Fast open                   : False
Keep alive count            : 10
Keep alive interval         : 1 sec
Fail on ICMP error          : False

[----- TCP information -----]
TCP state                   : Established
Maximum segment size        : 63.9 KiB
Connection time             : 24 min 6 sec ago (2025-04-15 11:17:37)
Timestamps enabled          : False
Estimated round-trip        : 147 us
Minimal round-trip          : 147 us
Bytes in flight             : 0 bytes
Congestion window           : 639 KiB
Send window                 : 63.9 KiB
Receive window              : 2.49 MiB
Receive buffer              : 2.49 MiB
Bytes sent                  : 0 bytes
Bytes received              : 0 bytes
Bytes reordered             : 0 bytes
Bytes retransmitted         : 0 bytes
Fast retransmits            : 0
Duplicate ACKs              : 0
Timeout episodes            : 0
SYN retransmits             : 0
Receiver-limited episodes   : 0
Receiver-limited time       : None
Receiver-limited bytes      : 0 bytes
Congestion-limited episodes : 0
Congestion-limited time     : None
Congestion-limited bytes    : 0 bytes
Sender-limited episodes     : 1
Sender-limited time         : None
Sender-limited bytes        : 2 bytes
Out-of-order packets        :
ECN negotiated              :
ECE ACKs                    :
Probe timeout episodes      :

[---- UDP-level options ----]
No checksum                 :
Maximum message size        :
Maximum coalesced size      :

[-- Hyper-V-level options --]
Connect timeout             :
Container passthru          :
Connected suspend           :
High VTL                    :

Complete.
```
