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


def Not_inside_tf_var(item, to_be_replaced):

  start = item.find(to_be_replaced)

  i = -1
  stack = 0
  initial_dollar = 0

  for char in item:
    i += 1
    if i == start:
      if stack == 0:
        return True
      else:
        return False

    if item[i - 1] != '\\' and stack > 0:
      if char == '{' and initial_dollar != (i - 1):
        stack += 1
      if char == '}':
        stack -= 1
        if stack == 0:
          tf_var = item[initial_dollar - 1:i + 1]

    if char == '{' and item[i - 1] == '$' and item[i - 2] != '\\' and stack == 0:
      initial_dollar = i
      stack = 1


def Subtitute_w_tf_vars(line, lobl, tf_file, directory):

  locals_block = Get_locals_block(lobl, tf_file, directory)

  api_suffix = '-api'

  subtitutes = []

  service_name = lobl.get('name')[1].replace('"','')

  unsc_service_name = service_name.replace('-', '_')

  for item in LOCALS_ORDER:
    subtitutes.append('${lookup(local.%s, "%s")}' % (unsc_service_name, item))

  for item in LOCALS_ORDER:
    if item != 'is_internal':
      subtitutes.append('${lookup(local.%s_api, "%s_api")}' % (unsc_service_name, item))


  regex_internal_str = '\\s*\\"internal\\"\\s+\\=.*'
  regex_fqdn_str = '.*%s\\.(\\$\\{terraform\\.workspace\\}(\\.|)|)(\\-net0ps|comtravo)\\.com.*' % service_name
  regex_fqdn_api_str = '.*%s-api\\.(\\$\\{terraform\\.workspace\\}\\.|)(\\-net0ps|comtravo)\\.com.*' % service_name
  regex_url_str = '.*http(|s)\\:\\/\\/%s' % regex_fqdn_str[2:]

  regex_internal = re.compile(regex_internal_str)
  regex_fqdn = re.compile(regex_fqdn_str)
  regex_url = re.compile(regex_url_str[:-2] + regex_fqdn_str)

  if service_name in line and line not in locals_block and ('=' in line or ':' in line):
    if re.match(re.compile(regex_url_str + Is_api_in_item(line)), line):
      line = re.sub((regex_url_str[2:-2] + api_suffix + regex_fqdn_str[len(service_name) + 2:-2]), subtitutes[6], line)
    elif re.match(re.compile(regex_url_str), line):
      print(line)
      line = re.sub(regex_url_str[2:-2], subtitutes[3], line)
    elif re.match(re.compile(regex_fqdn_api_str), line):
      line = re.sub(regex_fqdn_api_str[2:-2], subtitutes[5], line)
    elif re.match(re.compile(regex_fqdn_str), line):
      line = re.sub(regex_fqdn_str[2:-2], subtitutes[2], line)
    else:
      for item in Find_subtitution(line):
        if service_name in item and not '__' in item:
          to_be_replaced = service_name + Is_api_in_item(item)
          if not 'api' in to_be_replaced:
            replacement = subtitutes[1]
          else:
            replacement = subtitutes[4]
          if Not_inside_tf_var(item, to_be_replaced):
            line = line.replace(
              to_be_replaced,
              replacement
            )
  elif re.match(regex_internal, line):
    line = '"internal" = "%s"\n' % subtitutes[0]


  return line


def Get_tf_files_wo_locals(terraform_files):

  regex_definition_end = re.compile('\}.*')
  output = {}

  for key in terraform_files:
    with open(key) as file:
      capture_lines = False
      name_n_fqdn_in_locals = False
      locals_block = ''
      file_content = ''
      set_of_definitions = set()
      for line in file:
        file_content += line
        if 'locals {' in line:
          capture_lines = True
        if capture_lines:
          locals_block += line
        if regex_definition_end.match(line) and capture_lines:
          capture_lines = False
          break

    if len(locals_block) == 0 and not 'redirect_http_to_https' in file_content:
      return key


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

  tf_file_name = tf_file_name.replace('_', '-')

  return tf_file_name


def Is_api(tf_file, directory):

  command = (
    "grep -rP '.*%s-api.*' %s" % (
      tf_file,
      os.path.join(
        directory,
        'services/ct_backend_service_%s.tf' % (tf_file)
      )
    )
  )

  stdout = subprocess.getoutput(command)

  if len(stdout) < 1:
    return False
  else:
    return True


def Is_internal(tf_file, directory):

  command = ("grep -rP '\s*\"internal\"\s*\=\s*true' %s" % os.path.join(directory, 'ct_backend_service_%s.tf' % (tf_file.replace('-','_'))))
  stdout = subprocess.getoutput(command)

  if len(stdout) < 1:
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
  if Is_api(service_name, directory):
    service_name = service_name + '-api'
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
    ('__%s_url' % unsc_service_name, '"${local.__%s_is_internal ? "http" : "https"}://${local.__%s_fqdn}"' %
    (unsc_service_name, unsc_service_name))
  })

  return lobl


def Get_locals_block(lobl, tf_file, directory):

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
    locals_block += (
      '%s%s = %s\n' %
      (
        indent,
        key,
        '"${local.%s}"' % lobl.get(key)[0]
      )
    )

  indent = indent[:-2]

  locals_block += '%s}\n' % indent

  api_suffix = '-api'

  if Is_api(tf_file, directory) :
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


  new_content = Get_locals_block(lobl, tf_file, directory) + '\n' + file_content

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

  regex_url = re.compile('.*http(|s)\:\\/\\/.*')
  regex_fqdn = re.compile('.*(\\-net0ps|comtravo)\\.com.*')
  regex_internal = re.compile('\\s*internal\\s+\\=.*')

  locals_block = Get_locals_block(lobl, tf_file, directory)

  service_name = Tf_file_parse(tf_file)

  paths_to_files_to_be_subtituted = Get_tf_files_to_be_subtituted(tf_file, directory)


  for path_to_file in paths_to_files_to_be_subtituted:
    file_content = ''
    path_to_file = os.path.join(path_to_file)
    with open(path_to_file) as file:
      for line in file:
        file_content += Subtitute_w_tf_vars(line, lobl, tf_file, directory)
      file.close()

    new_content = file_content

    with open(path_to_file, 'w') as file:
      file.seek(0)
      file.write(new_content)
      file.close()

    print('Successfully subtituted vars in "%s"' % path_to_file)


def Tf_fmt(directory):

  command = "terraform fmt %s" % directory

  stdout = subprocess.getoutput(command)

  if len(stdout) > 0:
    if not 'Error' in stdout:
      print("Terraform format successfully apllied on:\n%s" % stdout)
    else:
      print("Terraform format found the followin error in:\n%s" % stdout)



def main():

  DIR = vars(parse_options()).get('directory')

  tf_files_dictionary = Get_tf_files_in_dir(DIR)
  
  tf_file = Get_tf_files_wo_locals(tf_files_dictionary)

  if tf_file != None:
    service_name = Tf_file_parse(tf_file)

    lobl = Get_locals(service_name, DIR)

    Prefix_locals_block(lobl, tf_file, DIR)

    Subtitute_tf_vars(lobl, tf_file, DIR)

    Tf_fmt(DIR)

  else:
    print("No files found")


if __name__ == "__main__":
  main()
