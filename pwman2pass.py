#!/usr/bin/env python
#
# pwman2pass.py takes in an unencrypted pwman db via filename or STDIN and uses 
# `pass' to import:
#
#   ./pwman2pass pwman.db.plain
#   gpg -d pwman.db | ./pwman2pass
# 
# your pwman db is imported into pass under a timestamped subfolder (in order
# to prevent overwriting any existing pass entries)
#
# Copyright (c) 2015, Calvin Ardi
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT
# HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import getopt, sys, select, re, random, time
import xml.etree.ElementTree as etree
from subprocess import Popen, PIPE

# used for path
timestamp = None;

def import_passwords(pwman_input, stdin):

  if stdin == True:
    xml_tree = etree.ElementTree(etree.fromstring(pwman_input))
  else:
    xml_tree = etree.parse(pwman_input)
  root = xml_tree.getroot()

  if(root.attrib['version'] != '3'):
    print "pwman db is not version 3 and unsupported."
    sys.exit(2)

  pwlist = root[0] # we should only have one main list
  if pwlist.tag == "PwList" and pwlist.attrib['name'] == "Main":
    processList(pwlist) 
  else:
    print "possibly malformed pwman db, exiting."
    sys.exit(2)

  print "import complete! stored under `%s'." % ("pwman-" + str(timestamp))

def processList(pwlist):
  listName = pwlist.attrib['name']
  print "[list] %s" % listName
  for node in pwlist:
    if node.tag == "PwList":
      processList(node)    
    elif node.tag == "PwItem":
      # this doesn't quite work if we have a sublist named "Main"
      processItem(node, sublist=(listName if listName != "Main" else None))
    else:
      print "encountered unknown tag: %s, exiting." % (node.tag)
      sys.exit(2)

# items have sub-elements name, host, user, passwd, and launch
# all sub-elements should exist and can be empty
def processItem(pwitem, sublist=None):
  entry = {node.tag: node.text for node in pwitem}
  print '[item] %s:%s%s' % (sublist if sublist != None else "Main", entry['name'], "") #entry)

  # only one level of fallback (XXX not complete)
  name = entry['name']
  if name.replace(" ", "") == "" or name == None:
    name = entry['host']
  
  # build path for pass (e.g., pwman-000000/sublist/entryName)
  path = "pwman-%s/%s%s" % (str(timestamp), (sublist + "/" if sublist != None else ""), name)

  # replace spaces with '-'
  path = re.sub('[ \t\r\n]', '-', path) 

  # sometimes passwords are empty
  pass_entry = "" if entry['passwd'] is None else entry['passwd'];

  tags = ['host', 'user', 'launch']
  for t in tags:
    if entry[t] != None and entry[t].replace(" ", "") != "":
      pass_entry = pass_entry + '\n' + t + ": " + entry[t]

  pass_entry = pass_entry + '\n'
  pass_insert(path, pass_entry)

def pass_insert(path, entry):
  pass_exec = Popen(['pass', 'insert', '--multiline', path], stdin=PIPE, stdout=PIPE)
  pass_exec.communicate(entry.encode('utf8'))

def usage():
  print "Usage: %s filename" % (sys.argv[0])

if __name__ == '__main__':

  stdin = None
  filename = None
  timestamp = int(time.time())

  # read from stdin if there's input from stdin
  if not sys.stdin.isatty():
    stdin = sys.stdin.read()
  elif len(sys.argv) > 1:
    # not checking or sanitizing input
    filename = sys.argv[1]
  else:
    usage()
    sys.exit(2)

  # check if we have pass installed
  try:
    p = Popen(['pass', 'version'], stdout=PIPE)
  except OSError as e:
    print "pass not installed? exiting."
    sys.exit(2)
  
  if stdin != None:
    import_passwords(stdin, stdin=True)
  elif filename != None:
    import_passwords(filename, stdin=False)
