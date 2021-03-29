#!/usr/bin/env python

import boto3
import ldap
import argparse
import time
import yaml
import logging
import sys
import json
import os.path as path
import os
from kubernetes import client, config
from logging.handlers import RotatingFileHandler

# Setup the log handlers to stdout and file.
parent_path = path.dirname(path.realpath(__file__))
log = logging.getLogger('ldap-eks-role-mapper')
log.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    )
handler_stdout = logging.StreamHandler(sys.stdout)
handler_stdout.setLevel(logging.DEBUG)
handler_stdout.setFormatter(formatter)
log.addHandler(handler_stdout)
handler_file = RotatingFileHandler(
  '{}/ldap-eks-role-mapper.log'.format(parent_path),
  mode='a',
  maxBytes=1048576,
  backupCount=9,
  encoding='UTF-8',
  delay=True
  )
handler_file.setLevel(logging.DEBUG)
handler_file.setFormatter(formatter)
log.addHandler(handler_file)

AD_USER_FILTER = '(&(objectClass=USER)(sAMAccountName={username}))'
AD_USER_FILTER2 = '(&(objectClass=USER)(dn={userdn}))'
AD_GROUP_FILTER = '(&(objectClass=GROUP)(cn={group_name}))'
AD_SERVERS = os.environ['AD_ADDRESS'] if os.getenv("AD_ADDRESS") is not None else ""
AD_BIND_USER = os.environ['AD_USERNAME'] if os.getenv("AD_USERNAME") is not None else ""
AD_BIND_PWD = os.environ['AD_PASSWORD'] if os.getenv("AD_PASSWORD") is not None else ""
AD_USER_BASEDN = os.environ['AD_BASE_DN'] if os.getenv("AD_BASE_DN") is not None else ""
PROTOCOL = "ldaps://" if os.getenv("IS_SECURE") is not None else "ldap://"

iam = boto3.client('iam')

# ldap connection
def ad_auth(username=AD_BIND_USER, password=AD_BIND_PWD, address=AD_SERVERS, protocol=PROTOCOL):
  conn = ldap.initialize(protocol + address)
  conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
  conn.protocol_version = 3
  conn.set_option(ldap.OPT_REFERRALS, 0)

  result = True

  try:
    conn.simple_bind_s(username, password)
    log.info("Succesfully authenticated")
  except ldap.INVALID_CREDENTIALS:
    log.error("Invalid credentials")
    return "Invalid credentials", False
  except ldap.SERVER_DOWN:
    log.error("Server down")
    return "Server down", False
  except ldap.LDAPError as e:
    if type(e.message) == dict and e.message.has_key('desc'):
      log.error("Other LDAP error: " + e.message['desc'])
      return "Other LDAP error: " + e.message['desc'], False
    else:
      log.error("Other LDAP error: " + e)
      return "Other LDAP error: " + e, False

  return conn, result

def get_dn_by_username(username, ad_conn, basedn=AD_USER_BASEDN):
  return_dn = ''
  ad_filter = AD_USER_FILTER.replace('{username}', username)
  results = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)
  if results:
    for dn, others in results:
      return_dn = dn
  return return_dn

#
# query only enabled users with the following filter
# (!(userAccountControl:1.2.840.113556.1.4.803:=2))
#
def get_email_by_dn(dn, ad_conn):
  email = ''
  result = ad_conn.search_s(dn.decode("utf-8"), ldap.SCOPE_BASE, \
    '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
  if result:
    for dn, attrb in result:
      if 'mail' in attrb and attrb['mail']:
        email = attrb['mail'][0].lower()
        break
  return email


def get_group_members(group_name, ad_conn, basedn=AD_USER_BASEDN):
  members = []
  ad_filter = AD_GROUP_FILTER.replace('{group_name}', group_name)
  result = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)
  if result:
    if len(result[0]) >= 2 and 'member' in result[0][1]:
      members_tmp = result[0][1]['member']
      for m in members_tmp:
        email = get_email_by_dn(m, ad_conn)
        if email:
          members.append(email)
  return members
  
def get_users_in_group(groupName):
  log.info('Gathering users for group {}!'.format(groupName))
  ad_conn, result = ad_auth()
  if result:
    group_members = get_group_members(groupName, ad_conn)
    return group_members

def update_configmap(mapRoles):
  v1 = client.CoreV1Api()
  name = 'aws-auth'
  namespace = 'kube-system'
  pretty = False
  exact = True
  export = True

  # Get current confimap
  try:
    api_response = v1.read_namespaced_config_map(name, namespace, pretty=pretty, exact=exact, export=export).to_dict()
    parsed = yaml.full_load(api_response['data']['mapRoles'])
    for data in parsed:
      if (data['username'] == 'system:node:{{EC2PrivateDNSName}}'):
        mapRoles.append(data)
    api_response['data']['mapRoles'] = yaml.dump(mapRoles)

  except ApiException as e:
    log.error("Exception when calling CoreV1Api->read_namespaced_config_map: %s\n" % e)

  # Update configmap
  try:
    api_response = v1.patch_namespaced_config_map(name, namespace, api_response, pretty=pretty)
    log.info('Configmap updated successfully!') 
  except ApiException as e:
    log.error("Exception when calling CoreV1Api->patch_namespaced_config_map: %s\n" % e)

def map_role_yaml_format(roleArn, k8sRoles, ldapGroup):
  mapRoles = []
  if (len(ldapGroup) == len(roleArn) and len(ldapGroup) == len(k8sRoles)):
    for group in ldapGroup:
      usersList = get_users_in_group(group)
      for user in usersList:
        mapRoles.append({
          'rolearn': roleArn[ldapGroup.index(group)],
          'username': "{}:{}".format(user.decode('utf-8'),'{{SessionName}}'),
          'groups': k8sRoles[ldapGroup.index(group)].split(','),
        })
    log.info('Mapping Roles!')
    return update_configmap(mapRoles)
  else:
    log.error('IAM group doesn\'t match to kubernetes roles. Please check your role mapping!')
    exit(1)

def main():
  log.info('Executing ldap-eks-role-mapper application!')
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
  parser.add_argument('--role_arn', default='arn:aws:iam::565284218568:role/AWSReservedSSO_AdministratorAccess_77b4790ba8ca2d2d', help='Role ARN to map')
  parser.add_argument('--ldap_group', default='devops', help='LDAP group')
  parser.add_argument('--kubernetes_roles', default='system:masters', help='Kubernetes cluster roles')
  parser.add_argument('--sleep_time', default=180, help='Time interval to refresh user mappings')
  args = parser.parse_args()
  roleArn = args.role_arn.split(';')
  ldapGroup = args.ldap_group.split(';')
  k8sRoles = args.kubernetes_roles.split(';')
  sleepTime = args.sleep_time # default: 2 minutes
  while True:
    map_role_yaml_format(roleArn, k8sRoles, ldapGroup)
    log.info('Sleeping for {} seconds'.format(sleepTime))
    time.sleep(int(sleepTime))

if __name__ == '__main__':
  main()