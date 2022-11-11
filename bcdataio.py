""" classes for reading/writing bitcoin data """
import struct
class Reader:
    """ helper class for reading data from a transaction """
    def __init__(self, fh):
        self.fh = fh
    def readbyte(self):
        data = self.readbytes(1)
        if not data:
            return
        b, = struct.unpack("<B", data)
        return b
    def readshort(self):
        data = self.readbytes(2)
        if not data:
            return
        w, = struct.unpack("<H", data)
        return w
    def readdword(self):
        data = self.readbytes(4)
        if not data:
            return
        w, = struct.unpack("<L", data)
        return w
    def readqword(self):
        data = self.readbytes(8)
        if not data:
            return
        w, = struct.unpack("<Q", data)
        return w
    def readvarint(self):
        b = self.readbyte()
        if b is None:
            return
        if b<0xfd:
            return b
        if b==0xfd:
            return self.readshort()
        if b==0xfe:
            return self.readdword()
        if b==0xff:
            return self.readqword()
    def readbytes(self, size):
        data = self.fh.read(size)
        if data and len(data)<size:
            raise Exception("not enough data")
        return data
    def readobject(self, objtype):
        obj = objtype()
        obj.decode(self)
        return obj

class Writer:
    """ helper class for writing data from a transaction """
    def __init__(self, fh):
        self.fh = fh
    def writebyte(self, b):
        self.fh.write(struct.pack("<B", b))
    def writeshort(self, w):
        self.fh.write(struct.pack("<H", w))
    def writedword(self, w):
        self.fh.write(struct.pack("<L", w))
    def writeqword(self, w):
        self.fh.write(struct.pack("<Q", w))
    def writevarint(self, x):
        if x<0xfd:
            self.writebyte(x)
        elif x<0x10000:
            self.writebyte(0xfd)
            self.writeshort(x)
        elif x<0x100000000:
            self.writebyte(0xfe)
            self.writedword(x)
        else:
            self.writebyte(0xff)
            self.writeqword(x)
    def writebytes(self, size):
        self.fh.write(size)
    def writeobject(self, obj):
        obj.encode(self)


