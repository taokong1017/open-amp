sudo apt install libsysfs-dev 

mkdir -p /home/ws/Src/openamp/build-libmetal
cd /home/ws/Src/openamp/build-libmetal
cmake ../libmetal
make VERBOSE=1 DESTDIR=$(pwd) install

mkdir -p /home/ws/Src/openamp//build-openamp
cd /home/ws/Src/openamp/build-openamp
cmake ../open-amp -DCMAKE_INCLUDE_PATH=/home/ws/Src/openamp/build-libmetal/usr/local/include \
-DCMAKE_LIBRARY_PATH=/home/ws/Src/openamp/build-libmetal/usr/local/lib -DWITH_APPS=ON -DWITH_SHARED_LIB=OFF
make VERBOSE=1 DESTDIR=$(pwd) install

sudo LD_LIBRARY_PATH=/home/ws/Src/openamp/build-openamp/usr/local/lib:/home/ws/Src/openamp/build-libmetal/usr/local/lib /home/ws/Src/openamp/build-openamp/usr/local/bin/rpmsg-echo-static

sudo LD_LIBRARY_PATH=/home/ws/Src/openamp/build-openamp/usr/local/lib:/home/ws/Src/openamp/build-libmetal/usr/local/lib /home/ws/Src/openamp/build-openamp/usr/local/bin/rpmsg-echo-ping-static 1

