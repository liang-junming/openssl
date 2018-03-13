#sun in sudo

#build target arm
cd openssl-1.0.0e
./config no-asm shared
sed -i '/CC= gcc/s/gcc/arm-none-linux-gnueabi-gcc/' Makefile
sed -i '/AR= ar/s/ar/arm-none-linux-gnueabi-ar/' Makefile
sed -i '/RANLIB= \/usr\/bin\/ranlib/s/\/usr\/bin\/ranlib/arm-none-linux-gnueabi-ranlib/' Makefile
sed -i '/NM= nm/s/nm/arm-none-linux-gnueabi-nm/' Makefile
make clean
make
make install
mv /usr/local/ssl ../ssl_out_arm

#build target host
./config no-asm shared
make clean
make
make install
mv /usr/local/ssl ../ssl_out_host
