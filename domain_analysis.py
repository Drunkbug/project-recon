import os
import socket
import pprint
import subprocess

def analysis_domains(contacted):
    domain_counts = {}
    for key in contacted.keys():
        try:
            ip = socket.gethostbyname(key)
            cmd = "whois " + ip + " | grep -E 'OrgName|descr|netname' | sed 's/   */ /g' | cut -d ' ' -f2"
            org_name = os.popen(cmd).read()
        except:
            print (key+": name or server not found")
            org_name = key

        if not org_name:
            continue
        org_name = org_name.replace('\n', '|')
        print ("org name: " + org_name)
        if (org_name in domain_counts.keys()):
            domain_counts[org_name] += contacted[key]
        else:
            domain_counts[org_name] = contacted[key]

    pprint.pprint(domain_counts)
    write_result(domain_counts)

def write_result(domain_counts):
    with open("result.txt", "w+") as f:
        for key in domain_counts.keys():
            line = str(key) + " : " + str(domain_counts[key]) + "\n"
            f.write(line)
