#!/usr/bin/env python3

import os
import sys
import re
import subprocess
import argparse

LOCALS_ORDER = [
  'is_internal',
  'name',
  'fqdn',
  'url'
]

def parse_options(operations=[]):
  '''
  parse cli
  '''
  parser = argparse.ArgumentParser(description=__doc__,
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument(
                        '--directory',
                        type=str,
                        help='Folder with Terraform files',
                        default='/home/ubuntu/ct-backend/terraform/services'
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

def Find_subtitution(line):

  i = -1
  stack = 0
  initial_qoutation_mark = 0
  closing_qoutation_mark = 1
  subtitutes = set()

  for char in line:
    i += 1
    if line[i] == '"':
      if stack == 1:
        stack -= 1
        closing_qoutation_mark = i
        subtitutes.add(line[initial_qoutation_mark:closing_qoutation_mark + 1])
      elif stack == 0:
        stack += 1
        initial_qoutation_mark = i

  return subtitutes


def Subtitute_w_tf_vars(line, lobl):

  locals_block = Get_locals_block(lobl)

  api_suffix = '-api'

  subtitutes = []

  service_name = lobl.get('name')[1].replace('"','')

  for item in LOCALS_ORDER:
    subtitutes.append('${lookup(local.%s, "%s")}' % (service_name, item))

  regex_internal_str = '\\s*internal\\s+\\=.*'
  regex_fqdn_str = '.*%s\\.(\\$\\{terraform\\.workspace\\}\\.|)(\\-net0ps|comtravo)\\.com.*' % service_name
  regex_fqdn_api_str = '.*%s-api\\.(\\$\\{terraform\\.workspace\\}\\.|)(\\-net0ps|comtravo)\\.com.*' % service_name
  regex_url_str = '.*http(|s)\:\\/\\/%s.*' % service_name

  regex_internal = re.compile(regex_internal_str)
  regex_fqdn = re.compile(regex_fqdn_str)
  regex_url = re.compile(regex_url_str[:-2] + regex_fqdn_str)

  if service_name in line and line not in locals_block and ('=' in line or ':' in line):
    if re.match(re.compile(regex_url_str + api_suffix), line):
      line = re.sub((regex_url_str[2:-2] + api_suffix + regex_fqdn_str[len(service_name) + 2:-2]), subtitutes[3], line)
    elif re.match(re.compile(regex_url_str), line):
      line = re.sub(regex_url_str[2:-2], subtitutes[3], line)
    elif re.match(re.compile(regex_fqdn_api_str), line):
      line = re.sub(regex_fqdn_api_str[2:-2], subtitutes[2], line)
    elif re.match(re.compile(regex_fqdn_str), line):
      line = re.sub(regex_fqdn_str[2:-2], subtitutes[2], line)
    else:
      for item in Find_subtitution(line):
        if service_name in item and not '__' in item:
          to_be_replaced = service_name + Is_api_in_item(item)
          replacement = subtitutes[1] + Is_api_in_item(item)
          line = line.replace(
            to_be_replaced,
            replacement
          )
  elif re.match(regex_internal, line):
    line = 'internal = ' + internal


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


def Is_api(tf_file, directory):

  command = ("grep -rP '.*%s-api.*' %s" % (tf_file, os.path.join(directory, 'services/ct_backend_service_%s.tf' % (tf_file))))
  stdout = subprocess.getoutput(command)

  if len(stdout) > 0:
    return False
  else:
    return True


def Is_internal(tf_file, directory):

  command = ("grep -rP '\s*\"internal\"\s*\=\s*true' %s" % os.path.join(directory, 'services/ct_backend_service_%s.tf' % (tf_file)))
  stdout = subprocess.getoutput(command)

  if len(stdout) > 0:
    return 'false'
  else:
    return 'true'


def Get_locals(service_name, directory):
  '''
  Return a dict with the following keys:
    internal
    name
    fqdn
    url
  Each key has a set as value that stands for the var name and the var value
  '''
  is_internal = Is_internal(service_name, directory)
  is_api = Is_api(service_name, directory)
  unsc_service_name = service_name.replace('-', '_')
  name = service_name

  lobl = {}

  lobl.update({'is_internal':
    ('__%s_is_internal' % unsc_service_name, '%s' % is_internal)
  })
  lobl.update({'name':
    ('__%s_name' % unsc_service_name, '"%s"' % name)
  })
  lobl.update({'fqdn':
    ('__%s_fqdn' % unsc_service_name, '"${local.__%s_name}.${terraform.workspace}${local.__%s_is_internal ? "-net0ps" : ".comtravo"}.com"' %
    (unsc_service_name, unsc_service_name))
  })
  lobl.update({'url':
    ('__%s_url' % unsc_service_name, '"${local.__%s_is_internal ? "http" : "https"} ://${local.__%s_fqdn}"' %
    (unsc_service_name, unsc_service_name))
  })

  if Is_api:
    lobl.update({'name-api':
      ('__%s_api_name' % unsc_service_name, '"${local.__%s_name}-api"' % unsc_service_name)
    })
    lobl.update({'fqdn-api':
      ('__%s_api_fqdn' % unsc_service_name, '"${local.__%s_name-api}.${terraform.workspace}${local.__%s_is_internal ? "-net0ps" : ".comtravo"}.com"' %
      (unsc_service_name, unsc_service_name))
    })
    lobl.update({'url-api':
      ('__%s_api_url' % unsc_service_name, '"${local.__%s_is_internal ? "http" : "https"} ://${local.__%s_fqdn-api}"' %
      (unsc_service_name, unsc_service_name))
    })


  return lobl


def Get_locals_block(lobl):

  locals_block = 'locals {\n'
  indent = '  '

  for key in LOCALS_ORDER:
    locals_block += (
      '%s%s = %s\n' %
      (
        indent,
        lobl.get(key)[0],
        lobl.get(key)[1]
      )
    )

  locals_block += (
    '%s%s = {\n' % 
    (
      indent,
      lobl.get('name')[1].replace('-', '_').replace('"', '')
    )
  )

  indent += '  '

  for key in LOCALS_ORDER:
    if key == 'name':
      locals_block += (
        '%s%s = %s\n' %
        (
          indent,
          key,
          '"${local.%s}"' % lobl.get(key)[0]
        )
      )
    else:
      locals_block += (
        '%s%s = %s\n' %
        (
          indent,
          key,
          lobl.get(key)[1]
        )
      )

  indent = indent[:-2]

  locals_block += '%s}\n' % indent

  api_suffix = '-api'

  locals_block += (
    '%s%s = {\n' % 
    (
      indent,
      (lobl.get('name')[1] + api_suffix).replace('-', '_').replace('"', '')
    )
  )

  indent += '  '

  for item in LOCALS_ORDER:
    if lobl.get(item + api_suffix) != None and item != 'is_internal':
      locals_block += (
        '%s%s = %s\n' %
        (
          indent,
          lobl.get(item + api_suffix)[0],
          lobl.get(item + api_suffix)[1]
        )
      )

  while '  ' in indent:
    indent = indent[:-2]
    locals_block += '%s}\n' % indent


  return locals_block


def Prefix_locals_block(lobl, tf_file, directory):

  path_to_file = os.path.join(directory, tf_file)
  service_name = Tf_file_parse(tf_file)

  with open(path_to_file) as file:
    file_content = ''
    for line in file:
      file_content += line


  new_content = Get_locals_block(lobl) + '\n' + file_content

  with open(path_to_file, 'w') as file:
    file.write(new_content)
    file.close()

  print('Successfully added locals block to "%s"' % path_to_file)


def Get_item_from_lobl(lobl, item):

  if lobl.get(item)[0] != None:
    return lobl.get(item)[0]
  else:
    return


def Get_tf_files_to_be_subtituted(tf_file, directory):

  service_name = Tf_file_parse(tf_file)
  command = ("grep -rl '%s' %s" % (service_name, os.path.join(directory)))
  stdout = subprocess.getoutput(command)

  return set(stdout.split('\n'))


def Is_api_in_item(item):

  if 'api' in item:
    return '-api'
  else:
    return ''


def Subtitute_tf_vars(lobl, tf_file, directory):

  '''
  for item in lobl:
    if 'name' in item[0]:
      name = item[0]
    elif 'url' in item[0]:
      url = item[0]
    elif 'fqdn' in item[0]:
      fqdn = item[0]
    elif 'internal' in item[0]:
      internal = item[0]

  service_name = Tf_file_parse(tf_file)

  command = ("grep -rl '%s' %s" % (service_name, os.path.join(directory)))
  stdout = subprocess.getoutput(command)

  paths_to_files_to_be_subtituted = set(stdout.split('\n'))
  '''

  regex_url = re.compile('.*http(|s)\:\\/\\/.*')
  regex_fqdn = re.compile('.*(\\-net0ps|comtravo)\\.com.*')
  regex_internal = re.compile('\\s*internal\\s+\\=.*')

  locals_block = Get_locals_block(lobl)

  service_name = Tf_file_parse(tf_file)

  paths_to_files_to_be_subtituted = Get_tf_files_to_be_subtituted(tf_file, directory)


  for path_to_file in paths_to_files_to_be_subtituted:
    file_content = ''
    path_to_file = os.path.join(path_to_file)
    with open(path_to_file) as file:
      for line in file:
        file_content += Subtitute_w_tf_vars(line, lobl)
      file.close()

    new_content = file_content

    with open(path_to_file, 'w') as file:
      file.seek(0)
      file.write(new_content)
      file.close()

    '''
    with open(path_to_file) as file:
      file_content = ''
      for line in file:
        if ('=' in line or ':' in line) and line not in locals_block:
          for item in Find_subtitution(line):
            if service_name in item and not '__' in item:
              if '"' in line:
                tf_var = '${local.%s}'
              else:
                tf_var = '"${local.%s}"'
              if 'http' in item:
                key = 'url' + Is_api_in_item(item)
                to_be_replaced = key
              elif '.com' in item:
                key = 'fqdn' + Is_api_in_item(item)
                to_be_replaced = service_name + Is_api_in_item(item) + '${terraform.workspace}'
              elif service_name in item:
                key = 'name' + Is_api_in_item(item)
                to_be_replaced = service_name + Is_api_in_item(item)
              #elif re.match(regex_internal, line):
              #  line = 'internal = ' + internal

              line = line.replace(
                to_be_replaced,
                tf_var % lobl.get(key)[0]
              )
    '''


    '''
              if '"' in item[1:-1]:
                tf_var = '${local.%s}'
              else:
                tf_var = '"${local.%s}"'
              if re.match(regex_url, item):
                line = line.replace(item, tf_var % url)
              elif re.match(regex_fqdn, line):
                line = line.replace(item, tf_var % fqdn)
              elif service_name in item:
                line = line.replace(item, name)
              elif re.match(regex_internal, line):
                line = 'internal = ' + internal
    '''

    '''
        if (
          ( '=' in line or ': "' in line )
          and service_name in line
          and not "policy" in line
          and not "role" in line
          and not '"image":' in line
          and not name in line
          and not url in line
          and not fqdn in line
          and not internal in line
          ):
          if '"' in line:
            tf_var = '${local.%s}'
          else:
            tf_var = '"${local.%s}"'
          if re.match(regex_url, line):
            line = line.replace(service_name, tf_var % url)
          elif re.match(regex_fqdn, line):
            line = line.replace(service_name, tf_var % fqdn)
          elif re.match(regex_internal, line):
            line = 'internal = ' + internal
          else:
            line = line.replace(service_name, tf_var % name)
    '''

    print('Successfully subtituted vars in "%s"' % path_to_file)



def main():

  DIR = vars(parse_options()).get('directory')

  tf_files_dictionary = Get_tf_files_in_dir(DIR)
  
  tf_file = Get_tf_files_wo_locals(tf_files_dictionary)

  service_name = Tf_file_parse(tf_file)

  lobl = Get_locals(service_name, DIR)

  Prefix_locals_block(lobl, tf_file, DIR)

  Subtitute_tf_vars(lobl, tf_file, DIR)

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
