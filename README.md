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
echo 1 > /proc/sys/net/ipv4/ip_forward

GATEWAY=192.168.1.1 INTERFACE=wlp4s0 TARGET=192.168.1.254
sudo arpspoof -i $INTERFACE -t $TARGET -r $GATEWAY

sudo yasu -i $INTERFACE -t $TARGET -p $PORT

# or if you want to see which packets pass on your machine you can simply type
sudo yasu -i $INTERFACE
```
###### Copyright © 2017, [Manu-sh](https://github.com/Manu-sh), s3gmentationfault@gmail.com. Released under the [GPL3 license](LICENSE).
