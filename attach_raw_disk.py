#!/openstack/venvs/nova-r14.0.0/bin/python
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
import logging
import logging.handlers
import urllib3
urllib3.disable_warnings()

'''Constants'''
LOG_FILENAME = "/var/log/nova/attach_raw_device.log"
OPENRC = "/root/openrc"
RAW_DISK_META_KEY = "raw_disk_serials"


def set_logging(logfile, log_level):
    log = logging.getLogger()
    log.setLevel(logging.INFO)
    format = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    if log_level == "DEBUG":
        ch = logging.StreamHandler()
        ch.setFormatter(format)
        log.addHandler(ch)

    fh = logging.handlers.RotatingFileHandler(
        logfile, maxBytes=(1048576 * 5), backupCount=7)
    fh.setFormatter(format)
    log.addHandler(fh)
    return log


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

    pipe = Popen('lsblk -o name,serial -dn', stdout=PIPE, shell=True)
    data = pipe.communicate()[0]
    for line in data.splitlines():
        if re.search(serial, line.strip()):
            device_name = line.split()[0]
            return device_name

    logger.info('Device with serial: %s not found!' % serial)
    return None


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
        logger.info('Searching for disk serial: %s' % serial)
        device_name = find_raw_disk(serial)
        logger.info('Device name for disk with serial: %s is %s'
                    % (serial, device_name))
        target_disk = find_next_disk(server_uuid)
        if device_name is not None:
            logger.info('Attaching device /dev/%s to Openstack server uuid: %s as device: %s' %
                        (device_name, server_uuid, target_disk))
            pipe = \
                Popen('virsh attach-disk --domain %s --source /dev/%s --type disk --target %s --live'
                      % (server_uuid, device_name, target_disk),
                      stdout=PIPE, shell=True)
            data = pipe.communicate()[0]


if len(sys.argv) > 1:
    logger = set_logging(LOG_FILENAME, "INFO")
    server_uuid = sys.argv[1]
    logger.info('Executing script: %s' % sys.argv[0])
    logger.info('Sourcing openrc variables')
    source_file(OPENRC)
    logger.info('Retriving server: %s metadata' % server_uuid)
    server = get_server(server_uuid)
    if RAW_DISK_META_KEY in server.metadata.keys():
        raw_disk_serials = server.metadata[RAW_DISK_META_KEY]
    else:
        logger.info('Openstack server object: %s does not have metadata key: %s' % (
            server_uuid, RAW_DISK_META_KEY))
        sys.exit(0)
    logger.info('Raw disk metadata for server: %s is: %s'
                % (server_uuid, raw_disk_serials))
    attach_disk(server_uuid, raw_disk_serials)

