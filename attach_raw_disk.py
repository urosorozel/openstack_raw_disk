#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Uros Orozel
# Date: 10/10/2017
# Desc: This script will retrive Opestack server metadata key raw_disk_serials
# loop over all disk serial numbers which are listed with lsblk and then try 
# attach raw device name to same virtual server with virtsh 

from keystoneauth1 import loading
from keystoneauth1 import session
from novaclient import client
from os import environ
from subprocess import Popen, PIPE
import sys
import os
import re
import syslog
import xml.etree.ElementTree as ET

import urllib3
urllib3.disable_warnings()

'''Openrc path'''
OPENRC = "/root/openrc"
RAW_DISK_META_KEY = "raw_disk_serials"

def source_file(script, update=True, clean=True):
    global environ
    if clean:
        environ_back = dict(environ)
        environ.clear()
    pipe = Popen('. %s; env' % script, stdout=PIPE, shell=True)
    data = pipe.communicate()[0]
    env = dict(line.split('=', 1) for line in data.splitlines())
    if clean:
        env.pop('LINES', None)
        env.pop('COLUMNS', None)
        environ = dict(environ_back)
    if update:
        environ.update(env)


def get_server(server_uuid):
    VERSION = 2.1
    USERNAME = environ['OS_USERNAME']
    PASSWORD = environ['OS_PASSWORD']
    AUTH_URL = environ['OS_AUTH_URL']
    extra_attributes = \
        {'user_domain_name': environ['OS_PROJECT_DOMAIN_NAME'],
         'project_name': environ['OS_PROJECT_NAME'],
         'project_domain_name': environ['OS_PROJECT_DOMAIN_NAME']}

    loader = loading.get_plugin_loader('password')
    auth = loader.load_from_options(auth_url=AUTH_URL,
                                    username=USERNAME,
                                    password=PASSWORD,
                                    **extra_attributes)
    sess = session.Session(auth=auth, verify=False)
    nova = client.Client(VERSION, session=sess)
    server = nova.servers.get(server_uuid)
    return server


def find_raw_disk(serial):
    ''' lsblk -o name,serial -dn'''

    pipe = Popen('lsblk1 -o name,serial -dn', stdout=PIPE, shell=True)
    data = pipe.communicate()[0]
    for line in data.splitlines():
        if re.search(serial, line.strip()):
            device_name = line.split()[0]
            return device_name


def find_next_disk(server_uuid):
    pipe = Popen('virsh domblklist %s' % server_uuid, stdout=PIPE,
                 shell=True)
    data = pipe.communicate()[0]
    reg = re.compile('^[sv]d[a-z]', re.MULTILINE)
    disks = reg.findall(data)
    last_disk = disks[-1]
    next_disk = last_disk[:2] + chr(ord(last_disk[2:]) + 1)
    return next_disk


def attach_disk(server_uuid, raw_disk_serials):
    for serial in raw_disk_serials.split(','):
        syslog.syslog('Searching for disk serial: %s' % serial)
        device_name = find_raw_disk(serial)
        syslog.syslog('Device name for disk with serial: %s is %s'
                      % (serial, device_name))
        target_disk = find_next_disk(server_uuid)
        pipe = \
            Popen('virsh attach-disk --domain %s --source /dev/%s --type disk --target %s --live'
                  % (server_uuid, device_name, target_disk),
                  stdout=PIPE, shell=True)
        data = pipe.communicate()[0]


if len(sys.argv) > 1:
    server_uuid = sys.argv[1]
    syslog.syslog('Executing script: %s' % sys.argv[0])
    syslog.syslog('Sourcing openrc variables')
    source_file(OPENRC)
    syslog.syslog('Retriving server: %s metadata' % server_uuid)
    server = get_server(server_uuid)
    raw_disk_serials = server.metadata[RAW_DISK_META_KEY]
    syslog.syslog('Raw disk metadata for server: %s is: %s'
                  % (server_uuid, raw_disk_serials))
    attach_disk(server_uuid, raw_disk_serials)
