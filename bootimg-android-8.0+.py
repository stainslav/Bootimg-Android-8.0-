#!/usr/bin/env python
#fileencoding: utf-8
#Author: Stainslav & Liu DongMiao <hellcolton01@gmail.com & liudongmiao@gmail.com>
#Created  : Sun 17 Oct 2010 11:19:58 AM CST
#Modified : Fri 04 Nov 2016 10:12:42 PM CST

import os
import sys
import mmap
import json
import struct
from stat import *
from hashlib import sha1

latin = lambda x: x.encode('latin')

def write_bootimg(output, kernel, ramdisk, second, dtimg,
        name, cmdline, kernel_addr, ramdisk_addr, second_addr, tags_addr, page_size, padding_size, os_version):
    ''' make C8600-compatible bootimg.
        output: file object
        kernel, ramdisk, second: file object or string
        name, cmdline: string
        base, page_size, padding_size: integer size

        official document:
        https://android.googlesource.com/platform/system/core/+/master/mkbootimg/bootimg.h

        Note: padding_size is not equal to page_size in HuaWei C8600
    '''
    if not isinstance(page_size, int):
        page_size = 0x800

    if not isinstance(padding_size, int):
        padding_size = 0x800

    if not hasattr(output, 'write'):
        output = sys.stdout

    padding = lambda x: struct.pack('%ds' % ((~x + 1) & (padding_size - 1)), latin(''))

    def getsize(x):
        if x is None:
            return 0
        assert hasattr(x, 'seek')
        assert hasattr(x, 'tell')
        x.seek(0, 2)
        return x.tell()

    def writecontent(output, x):
        if x is None:
            # sha.update('')
            sha.update(struct.pack('<I', 0))
            return None

        assert hasattr(x, 'read')

        x.seek(0, 0)
        content = x.read()
        sha.update(content)
        sha.update(struct.pack('<I', len(content)))
        output.write(content)
        output.write(padding(x.tell()))

        if hasattr(x, 'close'):
            x.close()

    output.write(struct.pack('<8s10I16s512s', latin('ANDROID!'),
        getsize(kernel), kernel_addr,
        getsize(ramdisk), ramdisk_addr,
        getsize(second), second_addr,
        tags_addr, page_size, getsize(dtimg), os_version,
        name, cmdline))

    idpos = output.tell()
    # fill with null first
    output.write(struct.pack('32s', latin('')))
    output.write(padding(output.tell()))
    sha = sha1()
    writecontent(output, kernel)
    writecontent(output, ramdisk)
    writecontent(output, second)
    writecontent(output, dtimg)
    # fill back sha1
    output.seek(idpos, 0)
    output.write(sha.digest())
    if hasattr('output', 'close'):
        output.close()

def parse_bootimg(bootimg):
    ''' parse C8600-compatible bootimg.
        write kernel to kernel[.gz]
        write ramdisk to ramdisk[.gz]
        write second to second[.gz]
        write dtimg to dt.img
        write extra to unknown

        official document:
        https://android.googlesource.com/platform/system/core/+/master/mkbootimg/bootimg.h

        Note: padding_size is not equal to page_size in HuaWei C8600
    '''

    (   magic,
        kernel_size, kernel_addr,
        ramdisk_size, ramdisk_addr,
        second_size, second_addr,
        tags_addr, page_size, dt_size, os_version,
        name, cmdline, id4x8
    ) = struct.unpack('<8s10I16s512s32s', bootimg.read(608))
    bootimg.seek(page_size - 608, 1)

    base = kernel_addr - 0x00008000
    assert magic.decode('latin') == 'ANDROID!', 'invald bootimg'
    # assert base == ramdisk_addr - 0x01000000, 'invalid bootimg'
    # assert base == second_addr - 0x00f00000, 'invalid bootimg'
    # assert base == tags_addr - 0x00000100, 'invalid bootimg'

    def say(v):
        b7 = 127
        b4 = 15
        a = (v >> 25) & b7
        b = (v >> 18) & b7
        c = (v >> 11) & b7
        y = ((v >>  4) & b7) + 2000
        m = v & b4
        return '%d.%d.%d %s-%s' % (a, b, c, y, m)
    sys.stderr.write('kernel_addr=0x%x\n' % kernel_addr)
    sys.stderr.write('ramdisk_addr=0x%x\n' % ramdisk_addr)
    sys.stderr.write('second_addr=0x%x\n' % second_addr)
    sys.stderr.write('tags_addr=0x%x\n' % tags_addr)
    # sys.stderr.write('base=0x%x\n' % base)
    sys.stderr.write('page_size=%d\n' % page_size)
    sys.stderr.write('os_version=0x%08x(%s)\n' % (os_version, say(os_version)))
    sys.stderr.write('name="%s"\n' % name.decode('latin').strip('\x00'))
    sys.stderr.write('cmdline="%s"\n' % cmdline.decode('latin').strip('\x00'))

    while True:
        if bootimg.read(page_size) == struct.pack('%ds' % page_size, latin('')):
            continue
        bootimg.seek(-page_size, 1)
        size = bootimg.tell()
        break

    padding = lambda x: (~x + 1) & (size - 1)
    sys.stderr.write('padding_size=%d\n' % size)
    metadata = {
        'kernel_addr': kernel_addr,
        'ramdisk_addr': ramdisk_addr,
        'second_addr': second_addr,
        'tags_addr': tags_addr,
        'page_size': page_size,
        'name': name.decode('latin').strip('\x00'),
        'cmdline': cmdline.decode('latin').strip('\x00'),
        'padding_size': size,
        'os_version': os_version,
    }
    w = open('bootimg.json', 'w')
    w.write(json.dumps(metadata))
    w.close()

    gzname = lambda x: x == struct.pack('3B', 0x1f, 0x8b, 0x08) and '.gz' or ''

    kernel = bootimg.read(kernel_size)
    output = open('kernel%s' % gzname(kernel[:3]) , 'wb')
    magic = struct.pack('>I', 0xd00dfeed)
    pos = kernel.find(magic)
    if pos > 0:
        output.write(kernel[:pos])
        kerneldt = open('kernel%s.dt' % gzname(kernel[:3]) , 'wb')
        kerneldt.write(kernel[pos:])
        kerneldt.close()
    else:
        output.write(kernel)
    output.close()
    bootimg.seek(padding(kernel_size), 1)

    ramdisk = bootimg.read(ramdisk_size)
    output = open('ramdisk%s' % gzname(ramdisk[:3]) , 'wb')
    output.write(ramdisk)
    output.close()
    bootimg.seek(padding(ramdisk_size), 1)

    if second_size:
        second = bootimg.read(second_size)
        output = open('second%s' % gzname(second[:3]) , 'wb')
        output.write(second)
        output.close()
        bootimg.seek(padding(second_size), 1)

    if dt_size:
        dtimg = bootimg.read(dt_size)
        output = open('dt.img', 'wb')
        output.write(dtimg)
        output.close()
        bootimg.seek(padding(dt_size), 1)

    unknown = bootimg.read()
    if unknown:
        output = open('unknown', 'wb')
        output.write(unknown)
        output.close()
    elif os.path.exists('unknown'):
        os.unlink('unknown')

    bootimg.close()

# CRC CCITT
crc_ccitt_table = []
for crc in range(0, 256):
    for x in range(0, 8):
        if crc & 0x1:
            crc = (crc >> 1) ^ 0x8408
        else:
            crc >>= 1
    crc_ccitt_table.append(crc)

def crc_ccitt(data, crc=0xffff):
    for item in data:
        crc = (crc >> 8) ^ crc_ccitt_table[crc & 0xff ^ item]
    return crc

def get_crc_ccitt(data):
    crc = crc_ccitt(data) ^ 0xffff
    return struct.pack('<H', crc)

POSITION = {0x30000000: 'boot.img',
            0x40000000: 'system.img',
            0x50000000: 'userdata.img',
            0x60000000: 'recovery.img',
            0xf2000000: 'splash.565',}
def parse_updata(updata, debug=False):
    ''' parse C8600 UPDATA binary.
        if debug is true or 1 or yes, write content to [position], else according POSITION

        UPDATA.APP Structure (only guess)
        magic                   |       0x55 0xaa 0x5a 0xa5
        header_length           |       unsigned int
        tag1                    |       0x01 0x00 0x00 0x00
        boardname               |       char[8]
        position                |       unsigned int
        content_length          |       unsigned int
        date                    |       char[16] -> YYYY.MM.DD
        time                    |       char[16] -> hh.mm.ss
        INPUT                   |       char[16] -> INPUT
        null                    |       char[16]
        crc                     |       crc-ccitt for header (98bit)
        tag2                    |       0x00 0x10 0x00 0x00
        header                  |       crc-ccitt for every 4096 of content
        content                 |
        padding                 |       padding to 4 bytes
    '''

    updatalist = open('updatalist.txt', 'w')
    while True:
        data = updata.read(4)
        if not data:
            break
        if data == struct.pack('4s', latin('')):
            continue

        data += updata.read(94)
        assert len(data) == 98, 'invalid updata'
        (   magic,
            header_length,
            tag1,       # \x01\x00\x00\x00
            boardname,
            position,
            content_length,
            date,
            time,
            INPUT,
            null,
            crc,
            tag2,       # \x00\x10\x00\x00
        ) = struct.unpack('<4sI4s8sII16s16s16s16s2s4s', data)

        magic, = struct.unpack('!I', magic)
        assert magic == 0x55aa5aa5, 'invalid updata %x' % magic

        header_header = list(struct.unpack('98B', data))
        header_header[-5] = header_header[-6] = 0
        assert crc == get_crc_ccitt(header_header)

        open('boardname.bin', 'wb').write(boardname)
        open('date.txt', 'wb').write(date)
        open('time.txt', 'wb').write(time)

        padding = (~(header_length + content_length) + 1) & 3

        remain = header_length - 98
        header = list(struct.unpack('%dB' % remain, updata.read(remain)))

        output = open(POSITION.get(position, '0x%x.raw' % position), 'wb')
        sys.stderr.write('%s\t0x%x\n' % (output.name, position))
        updatalist.write('%s\t0x%x\n' % (output.name, position))

        remain = content_length
        while remain > 0:
            size = remain > 4096 and 4096 or remain
            data = updata.read(size)
            if debug:
                check = list(struct.unpack('%dB' % size, data))
                check.append(header.pop(0))
                check.append(header.pop(0))
                assert crc_ccitt(check) == 0xf0b8
            output.write(data)
            remain -= size
        output.close()

        updata.seek(padding, 1)

    updata.close()
    updatalist.close()

def write_updata(output):
    '''
        magic                   |       0x55 0xaa 0x5a 0xa5
        header_length           |       unsigned int
        tag1                    |       0x01 0x00 0x00 0x00
        boardname               |       char[8]
        position                |       unsigned int
        content_length          |       unsigned int
        date                    |       char[16] -> YYYY.MM.DD
        time                    |       char[16] -> hh.mm.ss
        INPUT                   |       char[16] -> INPUT
        null                    |       char[16]
        crc                     |       crc-ccitt for header (98bit)
        tag2                    |       0x00 0x10 0x00 0x00
        header                  |       crc-ccitt for every 4096 of content
        content                 |
        padding                 |       padding to 4 bytes
    '''
    from time import strftime

    output.write(struct.pack('1s', latin('')) * 92)
    updatalist = open('updatalist.txt', 'r')
    boardname = open('boardname.bin', 'rb').read()
    if os.path.isfile('date.txt'):
        date = open('date.txt').read()
    else:
        date = strftime('%Y.%m.%d')
    if os.path.isfile('time.txt'):
        time = open('time.txt').read()
    else:
        time = strftime('%H.%M.%S')
    for record in updatalist:
        name, position = record.split()[:2]
        data = open(name, 'rb')
        header = latin('')
        content_length = 0
        while True:
            raw4096 = data.read(4096)
            content_length += len(raw4096)
            if not raw4096:
                break
            header += get_crc_ccitt(list(struct.unpack('%dB' % len(raw4096), raw4096)))
        header_length = 98
        header_length += len(header)
        data.close()

        header_header = struct.pack('<4sI4s8sII16s16s16s16s2s4s',
                latin('\x55\xaa\x5a\xa5'),
                header_length,
                latin('\x01\x00\x00\x00'),
                boardname,
                int(position, 16),
                content_length,
                latin(date),
                latin(time),
                latin('INPUT'),
                latin(''),
         
