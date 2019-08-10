#!/usr/bin/env python3

import os
import sys
import re
import subprocess
import argparse

def parse_options(operations=[]):
  '''
  parse cli
  '''
  parser = argparse.ArgumentParser(description=__doc__,
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument(
                        '--directory',
                        type=str,
                        help='Folder with Terraform files - Gets checked recursively including subdirectories',
                        default='/home/ubuntu/ct-backend/terraform'
                        #required=True
                      )

  return parser.parse_args()


def Get_tf_files_in_dir(dir):

  regex_tf_file = re.compile('ct_backend_service_\S+\.tf')
  terraform_files = {}

  for r, d, f in os.walk(dir):
    for file in f:
      if regex_tf_file.match(file):
        x = os.path.join(r, file)
        terraform_files.update({x:'null'})

  return terraform_files


def Subtitute_tf_vars(line):

  i = -1
  stack = 0
  initial_dollar = 0
  tf_var = ''
  var_replacement = 'some-var-here'

  for char in line:
    i += 1
    if line[i - 1] != '\\' and stack > 0:
      if char == '{' and initial_dollar != (i - 1):
        stack += 1
      if char == '}':
        stack -= 1
        if stack == 0:
          tf_var = line[initial_dollar - 1:i + 1]

    if char == '{' and line[i - 1] == '$' and line[i - 2] != '\\' and stack == 0:
      initial_dollar = i
      stack = 1

    if tf_var != '':
      lin_len = len(line)
      line = line.replace(tf_var, var_replacement)
      line = line.replace('""', '"')
      i -= lin_len - len(line)
      tf_var = ''

  return line

def Get_tf_files_wo_locals(terraform_files):

  regex_definition_end = re.compile('\}.*')
  output = {}

  for key in terraform_files:
    with open(key) as file:
      capture_lines = False
      name_n_fqdn_in_locals = False
      locals_block = ''
      set_of_definitions = set()
      for line in file:
        if 'locals {' in line:
          capture_lines = True
        if capture_lines:
          locals_block += line
        if regex_definition_end.match(line) and capture_lines:
          capture_lines = False
          break

    if len(locals_block) == 0:
      return key

'''
    if len(locals_block) > 0:
      if not 'name' in locals_block and 'fqdn' in locals_block:
        return key
    else:
      return key
'''

def Get_definition_from_tf_files(terraform_files):

  regex_definition_start = re.compile('\s*\S+\s=\s<<DEFINITION')
  regex_definition_end = re.compile('DEFINITION')
  output = {}

  for key in terraform_files:
    with open(key) as file:
      capture_lines = False
      definition = ''
      set_of_definitions = set()
      for line in file:
        if capture_lines and 'DEFINITION' not in line:
          line = Subtitute_tf_vars(line)
          definition += line
        if not capture_lines and regex_definition_start.match(line):
          capture_lines = True
        if capture_lines and regex_definition_end.match(line):
          capture_lines = False
          set_of_definitions.add(definition)
          definition = ''

      if len(set_of_definitions) > 0:
        output.update({key:set_of_definitions})

  return output


'''
def Print_status(errors, no_of_tf_files, no_of_definitions, directory):
  if len(errors) > 0:
    print('Invalid JSON found!\n')
    for tf_file in errors:
      print('In "%s" the following JSON error was found:\n===> %s\n' %
        (tf_file, str(errors.get(tf_file)))
      )

    return 1

  else:
    print('Scanned %s Terraform files and %s task definitions in "%s"' %
           (str(no_of_tf_files), str(no_of_definitions), directory))
    print('All JSONs seem to be valid - You are good to go!')
    return 0
'''

def Tf_file_parse(tf_file):

  tf_file_prefix = 'ct_backend_service'
  regex_tf_file = re.compile(tf_file_prefix + '\S+\.tf')

  tf_file_name = re.search(regex_tf_file, tf_file)

  tf_file_name = tf_file_name.group(0)[len(tf_file_prefix) + 1:-3]

  return tf_file_name


def Is_internal(tf_file, directory):

  command = ("grep -rP '\s*\"internal\"\s*\=\s*true' " + os.path.join(directory, 'services/ct_backend_service_%s.tf' % (tf_file)))
  stdout = subprocess.getoutput(command)

  if len(stdout) > 0:
    return True
  else:
    return False


def Get_locals_block(service_name, directory):

  internal = Is_internal(service_name, directory)
  unsc_service_name = service_name.replace('-', '_')

  lobl = []

  lobl.append('%s_is_internal = %s' % (unsc_service_name, internal))
  lobl.append('%s_name = "%s"' % (unsc_service_name, unsc_service_name))
  lobl.append('%s_fqdn = "${local.%s_name.${terraform.workspace}-%s' % (unsc_service_name, unsc_service_name, unsc_service_name))
  lobl.append('%s_url = "${%s_is_internal ? http://{locals.%s_fqdn}-net0ps.com : https://{locals.%s_fqdn}.comtravo.com}"' % (unsc_service_name, unsc_service_name, unsc_service_name, unsc_service_name))

  locals_block = 'locals {\n'

  for item in lobl:
    locals_block += '  %s\n' % (item)

  locals_block += '}'

  #print(locals_block)

  return locals_block



def main():

  DIR = vars(parse_options()).get('directory')

  tf_files_dictionary = Get_tf_files_in_dir(DIR)
  
  tf_file = Get_tf_files_wo_locals(tf_files_dictionary)

  service_name = Tf_file_parse(tf_file)

  Get_locals_block(service_name, DIR)

  task_definitions = Get_definition_from_tf_files(tf_files_dictionary)

'''
  exit_code = Print_status(
          errors,
          len(tf_files_dictionary),
          len(task_definitions),
          DIR
  )

  sys.exit(exit_code)
'''

if __name__ == "__main__":
  main()

