# To build the module type: 
#	make
# To load the module type: 
#	make load
# To unload the module type: 
#	make unload
# To clean the directory type:
#	make clean
# 

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

EXTRA_CFLAGS := -I$(src)/../include -I$(src)/../src -DHAVE_BOOL -D__KERNEL__ -Dlinux

MODULE := ntrusample
obj-m := $(MODULE).o

$(MODULE)-objs += __ntruEncrypt.o
$(MODULE)-objs += ../src/ntru_crypto_hmac.o
$(MODULE)-objs += ../src/ntru_crypto_hash.o
$(MODULE)-objs += ../src/ntru_crypto_msbyte_uint32.o
$(MODULE)-objs += ../src/ntru_crypto_sha1.o
$(MODULE)-objs += ../src/ntru_crypto_sha2.o
$(MODULE)-objs += ../src/ntru_crypto_sha256.o
$(MODULE)-objs += ../src/ntru_crypto_drbg.o
$(MODULE)-objs += ../src/ntru_crypto_ntru_convert.o
$(MODULE)-objs += ../src/ntru_crypto_ntru_encrypt.o
$(MODULE)-objs += ../src/ntru_crypto_ntru_encrypt_key.o
$(MODULE)-objs += ../src/ntru_crypto_ntru_encrypt_param_sets.o
$(MODULE)-objs += ../src/ntru_crypto_ntru_mgf1.o
$(MODULE)-objs += ../src/ntru_crypto_ntru_poly.o

MODULE.o:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

load:
	# load module passing
	sudo insmod ./$(MODULE).ko

unload:
	sudo rmmod $(MODULE)

clean:
	-@rm -fr *.o $(MODULE)*.o $(MODULE)*.ko *.mod.* *.order *.symvers *.markers *.*~ *~ .*.cmd .tmp_versions ../src/*.o

