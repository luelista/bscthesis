#!/usr/bin/env python2

import csv, json, sys, os, argparse, time, re
from chrome_remote_shell import Shell
from subprocess import Popen, check_output
from collections import Counter, defaultdict, OrderedDict
from urlparse import urlparse

def getsysvar(name):
    """
    Get a kernel config variable from sysctl
    """
    return check_output(['sysctl', '-n', name]).strip()

def pinghost(ping_hostname, intf = None):
    """
    Run the system's ping command and report back the packet and RTT statistics
    Optional parameter intf to specify the outgoing network interface
    """
    if len(ping_hostname) == 0: return ""
    # 4 pings should be sufficient to get meaningful results
    if intf is None:
        out = check_output(['ping', '-c', '4', '-i', '0.4', ping_hostname])
    else:
        out = check_output(['ping', '-c', '4', '-i', '0.4', ping_hostname, '-I', intf])

    s = out.strip().split("\n")

    pkg=re.match("(\d+) packets transmitted, (\d+) received, ([.\d]+)% packet loss, time (\d+)ms", s[-2])
    rtt=re.match("rtt min/avg/max/mdev = ([.\d]+)/([.\d]+)/([.\d]+)/([.\d]+) ms", s[-1])

    return {'pkg_tx': pkg.group(1),'pkg_tx': pkg.group(2),'loss': pkg.group(3),'time': pkg.group(4),
     'rtt_min': rtt.group(1), 'rtt_avg': rtt.group(2), 'rtt_max': rtt.group(3), 'rtt_mdev': rtt.group(4) }

def get_if_stat(ifname, statname):
    """
    Get network interface statistics. Possible values for statname e.g. "rx_bytes", "tx_bytes"
    """
    with open("/sys/class/net/"+ifname+"/statistics/"+statname, "r") as sf:
        return int(sf.readline())

def run_chrome_headless():
    """
    Run google chrome with (hopefully) all user interaction and automatic network requests disabled
    """
    os.environ["SSLKEYLOGFILE"] = "/tmp/sslkeys.log"
    FNULL = open(os.devnull, 'w')
    chrome_proc = Popen('google-chrome --ignore-certificate-errors --cipher-suite-blacklist=0xcc14,0xcc13 --remote-debugging-port=9876 --no-default-browser-check --user-data-dir=/tmp/chrome-profiling --no-first-run --disable-background-networking --disable-client-side-phishing-detection --disable-component-update --disable-default-apps --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --disable-web-resources --enable-logging --use-mock-keychain --dbus-stub --disable-translate --no-sandbox --password-store=basic about:blank'.split(' '),
        stdout=FNULL, stderr=FNULL)
    time.sleep(0.6)
    return chrome_proc

def connect_to_chrome():
    """
    Connect to a Google Chrome instance started by "run_chrome_headless" over the
    Chrome Debugging Protocol, wait for max. 10 seconds for Chrome to get ready
    """
    print "Waiting for chrome to be ready ",
    for i in range(100):
        print ".",
        sys.stdout.flush()
        try:
            # create debugging api client instance
            s = Shell(host='127.0.0.1', port=9876)
            for i, tab in enumerate(s.tablist):
                if tab['type'] == 'page':
                    # connect to the debugging api
                    s.connect(i, False)
                    print "connected"
                    return s
        except Exception, e:
            time.sleep(0.1)
    raise "No chrome found"

def store_with_prefix(dic, prefix, newdata):
    """
    Update a dictionary with values from another dictionary, but prefix all keys
    """
    dic.update({prefix+'_'+k : v for k,v in newdata.iteritems()})

def do_page_load(s, the_url, intf, intf2, timeout=30, verbose=0, extralogfield="-"):
    """
    Navigate to a page and return a dictionary containing network 
    statistics, page event timing and tracing data. Ping the destination before
    and after the page load over intf and, if set, intf2.
    """
    # the output dictionary, everything is collected in here
    QQ = OrderedDict()

    print ""
    print "URL: "+the_url
    QQ['url'] = the_url
    QQ['extraData'] = extralogfield

    s.do("Page.stopLoading")

    ping_hostname = urlparse(the_url).netloc
    if ":" in ping_hostname: ping_hostname = ping_hostname[0:ping_hostname.index(":")]
    try:
        store_with_prefix(QQ, 'pingBefore', pinghost(ping_hostname))
    except Exception, ex:
        print "pingBefore "+ping_hostname+" failed ("+str(ex)+")"
    QQ['bytesOnIntf1'] = get_if_stat(intf, "rx_bytes")
    if intf2:
        store_with_prefix(QQ, 'pingBeforeIntf2', pinghost(ping_hostname, intf2))
        QQ['bytesOnIntf2'] = get_if_stat(intf2, "rx_bytes")
    else:
        QQ['pingBeforeIntf2'] = {}
        QQ['bytesOnIntf2'] = 0

    s.do("Tracing.start", categories='blink.user_timing')
    clockSyncMarkerId = "ID_" + str(time.time())
    s.do("Tracing.recordClockSyncMarker", syncId = clockSyncMarkerId)
    time.sleep(0.05)
    # navigate to the page we want to profile
    s.do("Page.navigate", url=the_url)

    method = ""

    starttime=99999999
    endtime=0
    domReadyEventTime=0
    loadEventTime=0
    QQ['beforeDomReadySize']=0
    QQ['beforeLoadSize']=0
    overallSize=0

    requestsPerHost=Counter()
    bytesPerHost=defaultdict(float)
    bytesBeforeDomReadyPerHost=defaultdict(float)
    requestUrls = dict()
    requestDataTypes=dict()
    requestsPerDataType=Counter()
    bytesPerDataType=defaultdict(float)
    bytesBeforeDomReadyPerDataType=defaultdict(float)
    trackedLoads = dict()

    timeoutstart = time.time()
    # receive events until the main Page contents are fully loaded
    while method != "Page.loadEventFired":#"Page.frameStoppedLoading":
        if time.time() - timeoutstart > timeout:
                print "TIMEOUT of %d seconds, stopping"
                break
        method, params = s.receive_event()
        if not method: continue
        
        if method == 'Network.requestWillBeSent':
            requrl = params['request']['url']
            requestUrls[params['requestId']] = requrl

        if method == "Page.domContentEventFired":
            domReadyEventTime = params['timestamp']

        if method == 'Network.responseReceived':
            #the type of event is only known here, in Network.requestWillBeSent it is often 'Other'
            dataType=params['type'] 
            requestDataTypes[params['requestId']] = dataType

        if method == 'Network.loadingFinished':
            size=params['encodedDataLength'] #gzipped size

            # Only consider data of requests for the beforeXxxSize which was completed 
            # before the Xxx event fired. Requests which were not completed before the 
            # event fired probably has not influenced the event.
            if domReadyEventTime==0: QQ['beforeDomReadySize'] += size
            if loadEventTime==0: QQ['beforeLoadSize'] += size

            if params['requestId'] in requestUrls:
                url = requestUrls[params['requestId']]
                if url.startswith("http"): # it's named hostname, but really is the origin
                    hostname = url.split('/')[2]
                else: # if it doesn't start with http, it most likely is a data: uri
                    hostname = url[0:5]
            else:
                hostname = 'unknown'
            if domReadyEventTime==0: bytesBeforeDomReadyPerHost[hostname] += size
            requestsPerHost[hostname] += 1
            bytesPerHost[hostname] += size

            dataType = requestDataTypes.get(params['requestId'], 'Other')
            if domReadyEventTime==0: bytesBeforeDomReadyPerDataType[dataType] += size
            requestsPerDataType[dataType] += 1
            bytesPerDataType[dataType] += size

        if verbose > 2:
            # dump all the data
            print(params)

    # fetch tracing data
    tracingData = s.collect_tracing_data()
    if verbose > 2: print "tracingData =",tracingData

    print "Timings:"
    tracingData.sort(lambda a,b: a['ts']-b['ts'])
    firstFrameId = False
    for t in tracingData:
        if not firstFrameId:
            if t['name'] == 'navigationStart':
                firstFrameId = t['args']['frame']
                starttime = t['ts']
            else:
                continue
        if 'args' in t and 'frame' in t['args'] and firstFrameId == t['args']['frame'] and 'ts' in t:
            diff = float(t['ts']-starttime)/1000000
            print "%06.4f  %s"%(diff, t['name']) #, t['args']
            QQ[t['name']] = "%0.08f" % diff
        elif 'ts' in t and verbose > 1:
            diff = float(t['ts']-starttime)/1000000
            print "%06.4f  %s "%(diff, t['name']), t['args']
        elif verbose > 1:
            print "  --  %s "%( t['name']), t['args']

    print "before DOMContentReady: "+str(QQ['beforeDomReadySize']/1024)+"k"
    print "before Load: "+str(QQ['beforeLoadSize']/1024)+"k"

    print "#req\txferAll     \txferReady\torigin"
    QQ['origins'] = dict()
    for hostname in requestsPerHost.keys():
        print "% 4d\t% 8.2fk\t% 8.2fk\t%s" % (requestsPerHost[hostname], bytesPerHost[hostname]/1024, bytesBeforeDomReadyPerHost[hostname]/1024, hostname)
        QQ['origins'][hostname] = {'Requests':requestsPerHost[hostname], 'beforeLoadSize':bytesPerHost[hostname]/1024, 'beforeDomReadySize':bytesBeforeDomReadyPerHost[hostname]/1024}
    
    QQ['requestCount'] = sum(requestsPerHost.values())
    QQ['originCount'] = len(requestsPerHost)
    
    print "#req\txferAll     \txferReady\tDataType"
    QQ['dataTypes'] = dict()
    for dataType in requestsPerDataType.keys():
        print "% 4d\t% 8.2fk\t% 8.2fk\t%s" % (requestsPerDataType[dataType], bytesPerDataType[dataType]/1024, bytesBeforeDomReadyPerDataType[dataType]/1024, dataType)
        QQ[dataType+'BeforeLoadSize'] = bytesPerDataType[dataType]/1024
        QQ[dataType+'BeforeDomReadySize'] = bytesBeforeDomReadyPerDataType[dataType]/1024
        QQ[dataType+'Requests'] = requestsPerDataType[dataType]
    
    try:
        store_with_prefix(QQ, 'pingAfter', pinghost(ping_hostname))
    except Exception, ex:
        print "pingAfter "+ping_hostname+" failed ("+str(ex)+")"
    if intf2:
        store_with_prefix(QQ, 'pingAfterIntf2', pinghost(ping_hostname, intf2))
    else:
        pingAfterIntf2 = ""

    QQ['bytesOnIntf1'] = get_if_stat(intf, "rx_bytes") - QQ['bytesOnIntf1']
    if intf2:
        QQ['bytesOnIntf2'] = get_if_stat(intf2, "rx_bytes") - QQ['bytesOnIntf2']
    else:
        QQ['bytesOnIntf2'] = {}

    return QQ
    
FIELD_NAMES = [ "url", "extraData", "requestCount", "originCount", 
        "firstPaint", "firstContentfulPaint", "firstMeaningfulPaint", 
        "domContentLoadedEventStart", "loadEventStart", "beforeDomReadySize", "beforeLoadSize", 

        "DocumentRequests", "ScriptRequests", "StylesheetRequests", "FontRequests",
        "ImageRequests", "XHRRequests", "OtherRequests", 

        "DocumentBeforeDomReadySize", "ScriptBeforeDomReadySize", "StylesheetBeforeDomReadySize", 
        "FontBeforeDomReadySize", "ImageBeforeDomReadySize", "XHRBeforeDomReadySize", 
        "OtherBeforeDomReadySize", 

        "DocumentBeforeLoadSize", "ScriptBeforeLoadSize", "StylesheetBeforeLoadSize", 
        "FontBeforeLoadSize", "ImageBeforeLoadSize", "XHRBeforeLoadSize", "OtherBeforeLoadSize"
]


if __name__ == '__main__':
    # Handle command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="stores all possible meta data during the application execution", action="count", default=0)
    parser.add_argument("-e", "--extra", help="this is passed through to the logfile", default="-")
    parser.add_argument("-t", "--timeout", help="maximum time in seconds", default="-")
    parser.add_argument("-i", "--intf", help="name of the first intf", default="eth0")
    parser.add_argument("-j", "--intf2", help="name of the second intf", default=None)

    parser.add_argument("-l", "--logfile", help="path of the logfile", default="/tmp/webreq.log")
    parser.add_argument('urls', metavar='URL', type=str, nargs='+',
                        help='an URL to load')
    opt = parser.parse_args()
    urls=opt.urls

    # Open a CSV logfile and a JSON logfile
    logfilespec=opt.logfile
    do_header = not os.path.isfile(logfilespec)
    logfile=open(logfilespec,"a")
    logfile_json=open(logfilespec+'.json',"a")

    intf2 = opt.intf2
    intf = opt.intf

    out = csv.DictWriter(logfile, FIELD_NAMES, restval='-', extrasaction='ignore')
    if do_header:
        # Write the header only if the file was just created
        out.writeheader()

    # Start the browser and connect to the debugging API. "s" will hold reference to API.
    chrome_proc = run_chrome_headless()
    s = connect_to_chrome()
    time.sleep(1.5)

    # Enable receiving Page related events (esp. onLoad event)
    s.do("Page.enable")

    # Enable receiving Network profiling events
    s.do("Network.enable")

    # Load all pages which were specified as command line args
    for url in urls:
        s.do("Page.stopLoading")
        results=do_page_load(s, url, intf, intf2, timeout=opt.timeout, verbose=opt.verbose, extralogfield=opt.extra)
        # Write the results to CSV and JSON log file
        out.writerow(results)
        logfile_json.write(json.dumps(results)+'\n')
        s.do("Page.stopLoading")
        time.sleep(1.2)

    # close debugging API connection
    s.close()

    # close browser
    time.sleep(0.1)
    if opt.verbose > 0: print("sending KILL signal")
    chrome_proc.send_signal(9) #SIGKILL

    # delete the temporary profile folder to ensure "clean slate" for next run
    check_output(['rm', '-r', '/tmp/chrome-profiling'])

    logfile.close()
    logfile_json.close()
