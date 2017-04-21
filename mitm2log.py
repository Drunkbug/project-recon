#!/usr/bin/env python
#
# Date: 2016-07-12
# @author: JJ
#
# Function: .dump -> http(s).log, https.log
# mitmproxy >= 0.16, where libmproxy is deprecated
# mitmproxy: 0.17 response.msg => response.reason
# input: .dump
# ouput: _http.json, _https.json
#
from mitmproxy import flow
import json
import sys
import urllib
import pprint
import random
import string
import glob
import os
table_header = """#fields       ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       trans_depth     method  host
uri     referrer        user_agent      request_body_len        response_body_len       status_code     status_msg      info_code
info_msg        filename        tags    username        password        proxied orig_fuids      orig_mime_types resp_fuids
resp_mime_types content_length  content_encoding        content_type    transfer_encoding       post_body
client_header_names     client_header_values    server_header_names     server_header_values
""".replace('\n', '\t').strip()

def main():
    if len(sys.argv) < 2:
        print 'Usage: python %s dump_file [log_file_prefix]' % sys.argv[0]
        print '\nBy default, log_file_prefix=dump_file[:-5]'
        exit(-1)
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print 'User input should be a directory'
        exit(-1)
    os.chdir(directory)
    dump_files = glob.glob('./*.dump')
    #for dump_file in dump_files:
    #    if not dump_file.endswith('.dump'):
    #        print '!! There is something wrong with the dump file, maybe the naming.'
    #        print 'Usage: python %s dump_file [log_file_prefix]' % sys.argv[0]
    #        print '\nBy default, log_file_prefix=dump_file[:-5]'
    #        exit(-1)
    #if len(sys.argv) >= 3:
    #    log_file_prefix = sys.argv[2]
    #else:
    #print 'converting %s to %s_http(s).log' % (dump_file, log_file_prefix)
    result = run(dump_files)
    pprint.pprint(result)


def run(dump_files):
    num_http = 0
    num_https = 0
    err_cnt = 0
    contacted_domains = dict()
    for dump_file in dump_files:
        print (dump_file)
        json_file_prefix = dump_file[:-5]
        flow_json_http = []
        flow_json_https = []
        http_json_file_name ='%s_http.log' % (json_file_prefix)
        https_json_file_name ='%s_https.log' % (json_file_prefix)

        with open(dump_file, "rb") as logfile:
            f_reader = flow.FlowReader(logfile)
            line_http = 0
            line_https = 0
            for f in f_reader.stream():
                try:
                    ts = f.request.timestamp_start
                    # ts = '%.6f' % ts
                    # print ts
                    bro_uid = 'S{0}'.format(''.join(
                        random.choice(string.ascii_uppercase
                                      + string.ascii_lowercase
                                      + string.digits)
                        for _ in range(17)))
                    id_orig_h = f.client_conn.address.address[0]
                    id_orig_p = f.client_conn.address.address[1]
                    id_resp_h = f.request.host
                    id_resp_p = f.request.port
                    method = f.request.method
                    host = f.request.host
                    if 'host' in f.request.headers:
                        host = f.request.headers['host']

                    if host not in contacted_domains:
                        contacted_domains[host] = 0
                    contacted_domains[host] += 1
                    uri = f.request.path
                    referrer = ''
                    if 'referrer' in f.request.headers:
                        referrer = f.request.headers['referrer']
                    user_agent = '-'
                    if 'User-Agent' in f.request.headers:
                        user_agent = f.request.headers['User-Agent']
                    status_code = f.response.status_code
                    status_msg = f.response.reason
                    request_body_len, response_body_len = get_bytes(f)
                    trans_depth = '-'
                    info_code = '-'
                    info_msg = '-'
                    filename = '-'
                    tags = '(empty)'
                    username = '-'
                    password = '-'
                    proxied = '-'
                    orig_fuids = '-'  # 
                    orig_mime_types = '-'  
                    resp_fuids  = '-'
                    resp_mime_types = '-'
                    content_length = 0
                    content_encoding = '-'
                    content_type = '-'
                    if 'content-type' in f.request.headers:
                        content_type = f.request.headers['content-type']
                    if 'content-length' in f.request.headers:
                        content_length = f.request.headers['content-length']
                    transfer_encoding = '-'
                    post_body = '-'
                    if f.request.content is not None:
                        # make sure the content are in the same line, WHEN DECODING, replace /n with \n
                        post_body = urllib.quote(str(f.request.content))
                    # headers
                    client_header_names = ''
                    client_header_values = ''
                    for hk in f.request.headers:
                        hv = f.request.headers[hk]
                        client_header_names += '%s,' % hk

                        try:
                            hv = urllib.quote(hv)
                        finally:
                            client_header_values += '%s,' % hv
                    server_header_names = ''
                    server_header_values = ''
                    for hk in f.response.headers:
                        hv = f.response.headers[hk]
                        server_header_names += '%s,' % hk
                        try:
                            hv = urllib.quote(hv)
                        finally:
                            server_header_values += '%s,' % hv

                    http_entry = ''
                    http_entry += '%.6f\t%s\t%s\t%s\t%s\t%s\t' % (ts, bro_uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p)
                    http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (trans_depth, method, host, uri, referrer, user_agent)
                    http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (request_body_len, response_body_len, status_code,
                                                                status_msg, info_code, info_msg)
                    http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (filename, tags, username, password, proxied, orig_fuids)
                    http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (orig_mime_types, resp_fuids, resp_mime_types,
                                                                content_length, content_encoding, content_type)
                    http_entry += '%s\t%s\t%s\t%s\t%s\t%s' % (transfer_encoding, post_body, client_header_names,
                                                                client_header_values, server_header_names,
                                                                server_header_values)


                    if f.client_conn.ssl_established:
                        line_https += 1
                        flow_json_https.append(http_entry)
                    else:
                        line_http += 1
                        flow_json_http.append(http_entry)
                except flow.FlowReadError as v:
                    print "Flow file corrupted. Stopped loading."
                    print v.message
                    err_cnt += 1
                    json.dump(f.get_state(), sys.stdout, indent=4)
            num_http += len(flow_json_http)
            num_https += len(flow_json_https)
            if num_http > 0:
                with open(http_json_file_name, 'w') as hf:
                    hf.write(table_header + '\n')
                    for he in flow_json_http:
                        hf.write('%s\n' % he)
            if num_https > 0:
                with open(https_json_file_name, 'w') as hf:
                    hf.write(table_header + '\n')
                    for he in flow_json_https:
                        hf.write('%s\n' % he)
    result = dict()
    result['num_http'] = num_http
    result['num_https'] = num_https
    result['num_errors'] = err_cnt
    result['contacted'] = contacted_domains
    result['num_domains'] = len(contacted_domains)
    return result


def get_bytes(f):
    header = '%s %s %s\n' % (f.request.method, f.request.path, f.request.http_version)
    for h in f.request.headers:
        v = f.request.headers[h]
        header += '%s: %s\n' % (h, v)
    req_bytes = len(header)
    if f.request.content != '':
        req_bytes += len('\r\n') + len(f.request.content)

    if f.response is None:
        return [req_bytes, 0]
    header = '%s %s %s\n' % (f.response.http_version, f.response.status_code, f.response.reason)
    for h in f.response.headers:
        v = f.response.headers[h]
        header += '%s: %s\n' % (h, v)

    resp_bytes = len(header)
    if f.response.content is not None and f.response.content != '':
        resp_bytes += len('\r\n') + len(f.response.content)
    return [req_bytes, resp_bytes]

if __name__ == '__main__':
    main()
