sudo apt install libgmp-dev libtool -y &&
mkdir emp &&
cd emp &&
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py &&
python3 install.py --install --tool --ot &&
cd .. &&
sudo rm -rf emp &&
git clone https://github.com/osu-crypto/libOTe.git &&
cd libOTe &&
python3 build.py --all --boost --sodium &&
sudo python3 build.py --install &&
cd .. &&
sudo rm -rf libOTe