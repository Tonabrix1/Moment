#! /usr/bin/python3

import grequests, argparse, json, requests
from h2spacex import h2_frames, H2OnTlsConnection
from time import sleep
from urllib.parse import urlparse
from ast import literal_eval
from colorama import Fore, Style


headers = {}
settings = {}
body = {}
RATE_LIMIT = 50
DEFAULT_UA = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0'

def parser():
    parser = argparse.ArgumentParser(description="robust args")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-b", "--body", type=str)
    parser.add_argument("-s", "--sequencedata", type=str)
    parser.add_argument("-c", "--cookie", nargs="+", default=[])
    parser.add_argument("-a", "--uagent", default=DEFAULT_UA)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-r", "--rate", default=RATE_LIMIT, type=int)
    parser.add_argument("-o", "--output", default='output.json')
    parser.add_argument("-d", "--delimiter", default='=')
    parser.add_argument("-H", "--headers", type=str, default='')
    parser.add_argument("-p", "--port", default=443, type=int)
    parser.add_argument("-t", "--type", default='text', choices=['json'])
    parser.add_argument("-sp", "--singlepacket", default=0, type=int)
    return parser.parse_args()

def configure_session():
    args = parser()

    headers.update({k: v for k,v in (*[('Cookie',c) for c in args.cookie], ('User-Agent', args.uagent)) if v})
    if args.headers: headers.update({k.strip():v.strip() for k, v in [x.split(': ') for x in args.headers.splitlines()]})
    settings.update({
                    'url': args.url, 
                    'delimiter': args.delimiter,
                    'sequence': dict([args.sequencedata.split(args.delimiter)]),
                    'verbose': args.verbose,
                    'rate-limit': args.rate,
                    'body': args.body,
                    'output': args.output,
                    'header-string': args.headers,
                    'port': args.port,
                    'type': args.type,
                    'single-packet': args.singlepacket,
                    })
    if args.body:
        body.update({
            k:v if v not in ['true','false'] else literal_eval(v.capitalize()) for k,v in [x.split(args.delimiter) for x in args.body.split('&')]
        })
    if args.verbose:
        pretty_print("Settings:", settings)
        pretty_print("Headers:", headers)

#pretty print a dict with a header
def pretty_print(head, dct):
    print(head)
    for k, v in dct.items(): print(f"{k}: {v}")
    print()

def chunk(s, rate, num):
    chunks = max(num//rate,1)
    for _ in range(chunks):
        if (v:=[r for _ in range(rate) if (r:=next(s,''))]): yield v

#takes a string s and returns a sequence of substrings:
# if s == 'abc' the outputs will be ('a','ab','abc')
def get_sequence(s):
    for i in range(len(s)+1): yield s[:i]

#takes a substring from the sequence and returns a post body
def get_body(key, sub):
    if (t:=settings['type']) == 'json': return body | {key: sub}
    elif t == 'text': return '&'.join(f"{k}={v}" for k, v in [*body.items(), (key, sub)])

def append_seq(seq):
    return f"{u}?seq={seq}" if '?' not in (u:=settings['url']) else f"{u}&seq={seq}"

def format_prepped_request(prepped):
    # prepped has .method, .path_url, .headers and .body attribute to view the request
    body = prepped.body
    if body: body.encode()
    headers = '\n'.join([f'{k}: {v}' for k, v in prepped.headers.items()])
    return f"""{prepped.method} {prepped.path_url} HTTP/1.1\n{headers}\n\n{body}"""

#does quick analysis with a known password to see if timing attacks might be possible
def start():
    outp = {}
    k, v = next(iter(settings['sequence'].items()))
    seq = get_sequence(v)

    for ch in chunk(seq, settings['rate-limit'], len(v)):
        if (t:=settings['type']) == 'json': rs = (grequests.post(append_seq(c), json=get_body(k, c), headers=headers) for c in ch)
        elif t == 'text': rs = (grequests.post(append_seq(c), data=get_body(k,c), headers=headers) for c in ch)
        for resp in grequests.map(rs):
            if resp is None: 
                print("failed to get response...")
                continue
            
            resps = [resp] + resp.history
            for r in resps:
                outp[r.url] = {
                    'status_code': r.status_code,
                    'response_time': r.elapsed.total_seconds(),
                }
                if settings['verbose']: outp[r.url] |= {'request': format_prepped_request(r.request), 'response': r.text}
    return seq, outp

def create_single_packets(bodies):
    #single packet attack using h2spacex as demonstrated in the docs
    parsed = urlparse(settings['url'])


    h2_conn = H2OnTlsConnection(
        hostname=parsed.netloc,
        port_number=settings['port']
    )

    h2_conn.setup_connection()

    head = build_header_string()

    try_num = len(bodies)

    stream_ids_list = h2_conn.generate_stream_ids(number_of_streams=try_num)

    all_headers_frames = []  # all headers frame + data frames which have not the last byte
    all_data_frames = []  # all data frames which contain the last byte

    temp_string = ''

    for i in range(0, try_num):
        header_frames_without_last_byte, last_data_frame_with_last_byte = h2_conn.create_single_packet_http2_post_request_frames(
            method='POST',
            headers_string=head+f'Content-Length: {len(bodies[i])}\n',
            scheme=parsed.scheme,
            stream_id=stream_ids_list[i],
            authority=parsed.netloc,
            body=bodies[i],
            path=parsed.path
        )

        all_headers_frames.append(header_frames_without_last_byte)
        all_data_frames.append(last_data_frame_with_last_byte)

        # concatenate all headers bytes
    temp_headers_bytes = b''
    for h in all_headers_frames: temp_headers_bytes += bytes(h)


    # concatenate all data frames which have last byte
    temp_data_bytes = b''
    for d in all_data_frames: temp_data_bytes += bytes(d)

    #print(temp_headers_bytes, temp_data_bytes, sep='\n\n')

    h2_conn.send_bytes(temp_headers_bytes)

    # wait some time
    sleep(0.1)

    # send ping frame to warm up connection
    h2_conn.send_ping_frame()

    # send remaining data frames
    h2_conn.send_bytes(temp_data_bytes)

    resp = h2_conn.read_response_from_socket(_timeout=5)
    frame_parser = h2_frames.FrameParser(h2_connection=h2_conn)
    frame_parser.add_frames(resp)
    frame_parser.show_response_of_sent_requests()

    print('---')

    print(temp_string)

    sleep(3)
    h2_conn.close_connection()

def analyze(sequence, outp):
    outp = dict(sorted(outp.items(), key=lambda x: x[1]['response_time']))
    print(json.dumps(outp, indent=2))
    keylist = [*outp]
    possible = True and outp
    for i in range(len(keylist)):
        if len(keylist[i-1]) > len(keylist[i]): possible = False
    if possible: print(Fore.RED,"TIMING ATTACK POSSIBLE!")
    

def build_header_string():
    #removes trailing newlines and content length headers automatically
    outp = h.rstrip('\n')+'\n' if (h:='\n'.join([x for x in settings['header-string'].splitlines() if 'Content-Length' not in x])) else ''
    outp += '\n'.join(f"{k}: {v}" for k,v in headers.items())
    return outp

if __name__ == "__main__":
    configure_session()
    resp = start()
    analyze(*resp)
    
    if sp:=settings['single-packet']:

        k, v = next(iter(settings['sequence'].items()))
        seq = get_sequence(v)

        #bodies = [json.dumps(body | {k : c}) for c in seq][-3:]
        bodies = [get_body(k, v) for _ in range(sp)]
        create_single_packets(bodies)