#!/usr/bin/env python
#
# Extract BSSID/SSID/Channel from Beacon and Probe Response frames in a capture file
#

import sys, getopt
import subprocess
import re

def usage():
   print "%s -i <capture-file>" % (__file__)

def main(argv):
   try:
      opts, args = getopt.getopt(argv,"hi:",["ifile="])
      if not opts:
         print 'No input file supplied'
         usage()
         sys.exit(2)
   except getopt.GetoptError, e:
      print e
      usage()
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         usage()
         sys.exit()
      elif opt in ("-i", "--ifile"):
         filename = arg
   return filename

if __name__ == "__main__":
   filename = main(sys.argv[1:])
   list = []
   dalist = []
   salist = []
   #argv = ["-ennr", filename, "(type mgt subtype beacon) || (type mgt subtype probe-resp)"]
   argv = ["-ennr", filename]
   cmd = subprocess.Popen(["tcpdump"] + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
   print ('  {: <18} {: <25} {: <6} {: <8} {: <10}'.format('BSSID','SSID','Signal','Channel', 'Frequency'))
   for line in cmd.stdout:
      #print line;
      da = re.search(r'(DA:)(\w+\:\w+\:\w+\:\w+\:\w+\:\w+)', line)
      sa = re.search(r'(SA:)(\w+\:\w+\:\w+\:\w+\:\w+\:\w+)', line)
      if 'Beacon' in line:
         bssid = re.search(r'(BSSID:)(\w+\:\w+\:\w+\:\w+\:\w+\:\w+)', line)
         if bssid.group(2) not in list :
            list.append(bssid.group(2))

            ssid = re.search(r'(Beacon\s\()(.+?(?=\)))', line)
            signal = re.search(r'((-.*) signal)', line)
            channel = re.search(r'(CH:\s)(\w)', line)
            frequency = re.search(r'(.{4} MHz)', line)

            print '  {: <18} {: <25} {: <6} {: <8} {: <10}'.format(bssid.group(2), ssid.group(2), signal.group(2), channel.group(2), frequency.group(1))
      
      elif 'Probe Response' in line:
         bssid = re.search(r'(BSSID:)(\w+\:\w+\:\w+\:\w+\:\w+\:\w+)', line)
         if bssid.group(2) not in list :
            list.append(bssid.group(2))
            ssid = re.search(r'(Probe Response\s\()(.+?(?=\)))', line)
            channel = re.search(r'(CH:\s)(\w)', line)
            if ssid:
               print "* {: <18} {: <25} {: <6} {: <8} {: <10}".format(bssid.group(2), ssid.group(2), signal.group(2), channel.group(2), frequency.group(1))
            else:
                  print "%s\t<hidden>\t%s\t*" %(bssid.group(2), channel.group(2))
      
      #elif 'Data' in line:

      #   print line;
      #if da.group(2) not in dalist:
       #  dalist.append(da.group(2))
        # print '{: <18} {: <25}'.format(da.group(2), sa.group(2))
            #print da.group(2);

         #if sa.group(2) not in salist:
            #salist.append(sa.group(2))
            #print sa.group(2);
   print ("\n* = Probe Response\n")
 
