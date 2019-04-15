a) Reused Code: No
b) Complete: Yes
c) Diversion of HTTP and HTTPS: Since the unmodified browser would send HTTPS request directly to server address and port 443. This request doesn't match iptables redirect rules and will be sent out by R2. So squid cannot intercept this request.

d) Diversion of HTTP and HTTPS take 2: we can modify browser by sending HTTPS request to proxy server (dest=127.0.0.1 dport=3128)

