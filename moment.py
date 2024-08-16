import grequests, argparse, json

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
    return parser.parse_args()

def configure_session():
    args = parser()

    headers.update({k: v for k,v in (('Cookie',args.cookie), ('User-Agent', args.uagent)) if v})
    settings.update({
                    'url': args.url, 
                    'delimiter': args.delimiter,
                    'sequence': dict([args.sequencedata.split(args.delimiter)]),
                    'verbose': args.verbose,
                    'rate-limit': args.rate,
                    'body': args.body,
                    'output': args.output,
                    })
    if args.body:
        body.update({
            k:v for k,v in [x.split(args.delimiter) for x in args.body.split('&')]
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
def get_body(sub):
    body = {}

#does quick analysis with a known password to see if timing attacks might be possible
def start():
    outp = {}
    k, v = next(iter(settings['sequence'].items()))
    seq = get_sequence(v)
    for ch in chunk(seq, settings['rate-limit'], len(v)):
        rs = (grequests.post(f"{settings['url']}?seq={c}", json=body | {k: c}, headers=headers) for c in ch)
        for resp in grequests.map(rs):
            if resp is None: 
                print("failed...")
                continue
            outp[resp.url] = {
                'status_code': resp.status_code,
                'response_time': resp.elapsed.total_seconds(),
            }
    return seq, outp

def analyze(sequence, outp):
    outp = dict(sorted(outp.items(), key=lambda x: x[1]['response_time']))
    print(json.dumps(outp, indent=2))


if __name__ == "__main__":
    configure_session()
    resp = start()
    analyze(*resp)