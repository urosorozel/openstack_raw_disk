#!/bin/bash
# Author: Uros Orozel
# Date: 9/10/2017
# Desc: This script will execute "at now" job with Openstack uuid of VM as first argument
# only execute at job on "started state"
if [[ $2 = "started" ]];then
  read UUID < <(cat - | grep -oP '(?<=<uuid>).*?(?=</uuid>)')
  CMD="/usr/local/bin/attach-raw-device.py ${UUID}"
  echo $CMD | at now
fi