# Tufw
Ufw terminal frontend based on dialog

![tufw image](./tufw.png)

# 
## Installation
Tufw **NEEDS** to be installed as root, because it needs to run as root and python won't load the module if it's installed as a normal user.

```sh
sudo python3 -m pip install tufw
# OR
sudo pip3 install tufw
```
Obviously Tufw needs [`dialog`](https://invisible-island.net/dialog/), so install it with
```sh
sudo apt install dialog
```
or whatever you use on your distribution.

>While [vermin](https://github.com/netromdk/vermin) reports minimum python version for Tufw is 3.0, it has been tested only with python 3.5.4 and 3.10. Older versions have not been tested yet.
# 
## Running
As ufw, Tufw needs to be run as root.
```sh
sudo tufw
```
I know typing '`sudo `' (space included) is always tiring and easy to forget and ufw refuses to work without, so Tufw can self elevate, calling sudo itself if you forget to.

You can just type:
```sh
tufw
```
# 
## Give to Caesar what is Caesar's
This project comes from my need to have a simple frontend for ufw like [@costales](https://github.com/costales)' [gufw](https://github.com/costales/gufw), but character based, to install on my headless server, so the code in `firewall.py` comes from costales' work, simplified a bit, but still his work.

#
#

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/a13ssandr0)

[<img src="https://raw.githubusercontent.com/aha999/DonateButtons/master/Paypal.png" width="200">](https://www.paypal.com/donate/?hosted_button_id=9RHPMJAS26TJN)
