ZLIBPATH = ./3rd/zlib
MD5PATH = ./3rd/md5

ZLIBOBJS = $(ZLIBPATH)/crc32.obj $(ZLIBPATH)/adler32.obj $(ZLIBPATH)/inffast.obj $(ZLIBPATH)/zip.obj $(ZLIBPATH)/deflate.obj\
$(ZLIBPATH)/inflate.obj $(ZLIBPATH)/inftrees.obj $(ZLIBPATH)/ioapi.obj $(ZLIBPATH)/unzip.obj $(ZLIBPATH)/zutil.obj $(ZLIBPATH)/trees.obj
OBJS = example.obj pkcs7.obj $(MD5PATH)/md5.obj $(ZLIBOBJS)

ALL:$(OBJS)
	link /subsystem:console *.obj -out:example.exe
.c.obj::
	cl -c -O2 $<

.cpp.obj::
	cl -c -O2 $<



	
clean:
	erase *.obj
	erase *.exe