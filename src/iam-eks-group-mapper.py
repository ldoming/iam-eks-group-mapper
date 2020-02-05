#!/usr/bin/env python

import boto3
import argparse
import time
import yaml
import logging
import sys
import os.path as path
from kubernetes import client, config
from logging.handlers import RotatingFileHandler

# Setup the log handlers to stdout and file.
parent_path = path.dirname(path.realpath(__file__))
log = logging.getLogger('iam-eks-group-mapper')
log.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    )
handler_stdout = logging.StreamHandler(sys.stdout)
handler_stdout.setLevel(logging.DEBUG)
handler_stdout.setFormatter(formatter)
log.addHandler(handler_stdout)
handler_file = RotatingFileHandler(
  '{}/iam-eks-group-mapper.log'.format(parent_path),
  mode='a',
  maxBytes=1048576,
  backupCount=9,
  encoding='UTF-8',
  delay=True
  )
handler_file.setLevel(logging.DEBUG)
handler_file.setFormatter(formatter)
log.addHandler(handler_file)

iam = boto3.client('iam')

def get_user_in_group(groupName):
  log.info('Gathering users for group {}!'.format(groupName))
  groupUsers = []
  for userlist in iam.list_users()['Users']:
      userGroups = iam.list_groups_for_user(UserName=userlist['UserName'])
      for group in userGroups['Groups']:
        if group['GroupName'] == groupName:
          groupUsers.append(userlist)
  return groupUsers

def update_configmap(mapUsers):
  v1 = client.CoreV1Api()
  name = 'aws-auth'
  namespace = 'kube-system'
  pretty = False
  exact = True
  export = True

  # Get current confimap
  try:
    api_response = v1.read_namespaced_config_map(name, namespace, pretty=pretty, exact=exact, export=export).to_dict()
    api_response['data']['mapUsers'] = mapUsers
  except ApiException as e:
    log.error("Exception when calling CoreV1Api->read_namespaced_config_map: %s\n" % e)

  # Update configmap
  try:
    api_response = v1.patch_namespaced_config_map(name, namespace, api_response, pretty=pretty)
    log.info('Configmap updated successfully!') 
  except ApiException as e:
    log.error("Exception when calling CoreV1Api->patch_namespaced_config_map: %s\n" % e)

def map_user_yaml_format(iamGroups, k8sRoles):
  mapUsers = []
  if (len(iamGroups) == len(k8sRoles)):
    for group in iamGroups:
      usersList = get_user_in_group(group)
      for user in usersList:
        mapUsers.append({
          'userarn': user['Arn'],
          'username': user['UserName'],
          'groups': k8sRoles[iamGroups.index(group)].split(','),
        })
    log.info('Mapping users!')
    return update_configmap(yaml.dump(mapUsers))
  else:
    log.error('IAM group doesn\'t match to kubernetes roles. Please check your role mapping!')
    exit(1)

def main():
  log.info('Executing iam-eks-group-mapper application!')
  try:
    log.info("Trying in cluster API connection")
    config.load_incluster_config()
    log.info('Python client connected successfully!')
  except:
    log.warning('Unable to connect though incluster connection!')
    try:
      log.info("Trying in kubeconfig API connection")
      config.load_kube_config()
      log.info('Python client connected successfully!')
    except:
      log.error("Unable to connect to API")

  parser = argparse.ArgumentParser()
  parser.add_argument('--iam_groups', default='admin;devs', help='IAM groups')
  parser.add_argument('--kubernetes_roles', default='system:masters;system:aggregate-to-view', help='Kubernetes cluster roles')
  parser.add_argument('--sleep_time', default=120, help='Time interval to refresh user mappings')
  args = parser.parse_args()
  iamGroups = args.iam_groups.split(';')
  k8sRoles = args.kubernetes_roles.split(';')
  sleepTime = args.sleep_time # default: 2 minutes
  while True:
    map_user_yaml_format(iamGroups, k8sRoles)
    log.info('Sleeping for {} seconds'.format(sleepTime))
    time.sleep(sleepTime)

if __name__ == '__main__':
  main()