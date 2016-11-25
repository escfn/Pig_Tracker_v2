#!/usr/bin/python

# -------------------------------------------------------------------------------------------------------------------------- #
#                     .g8888bgd 
#                   .dP       M 
# ,pP"Ybd  ,pW8Wq.  dM        ; 
# 8I      6W     Wb MM          
#  YMMMa. 8M     M8 MM.         
# L.   I8 YA.   ,A9  Mb.     , 
# M9mmmP;  .Ybmd9.    ..bmmmd.
# -------------------------------------------------------------------------------------------------------------------------- #
import sys  
sys.path.append('core')
from imports import *
# -------------------------------------------------------------- #

def exit():
	os.system("clear")
	raise SystemExit
# --------------------------------------------------------------------------------------- #
def com_error():
    print '\033[1;31mSorry, that was an invalid command!\033[1;m'.center(termwidth)
# --------------------------- Start Menu Banners ---------------------------------------- #
def banner():
    os.system("clear")
    thetext = """\033[1;36m
         _____ _         _______             _             
        |  __ (_)       |__   __|           | |            
        | |__) |  __ _     | |_ __ __ _  ___| | _____ _ __ 
        |  ___/ |/ _` |    | | '__/ _` |/ __| |/ / _ \ '__|
        | |   | | (_| |    | | | | (_| | (__|   <  __/ |   
        |_|   |_|\__, |    |_|_|  \__,_|\___|_|\_\___|_|   
                  __/ |                                    
                 |___/     Version: 2.0 {soC} \033[1;m"""
    print "\033[1;32m-\033[1;m"*width+"\n"+"\n"+(thetext).center(termwidth)+"\n"+"\n"+"\033[1;32m-\033[1;m"*width
# --------------------------------------------------------------------------------------- #
def bluetooth_scan_banner():
    print ' \033[1;36mBluetooth Module\033[1;m '.center(termwidth, fillchar)
    print "\n"
    print ("\033[1;32m1\033[1;m) \033[1;36m Scan \033[1;m").center(termwidth)+"\n"
# --------------------------------------------------------------------------------------- #
def menu1():    
    print "\033[1;32m-\033[1;m"*width+"\n"+"\n"+"\033[1;32m1\033[1;m) \033[1;36m Wifi Module \033[1;m"+"\n"+"\n"+"\033[1;32m2\033[1;m) \033[1;36m Bluetooth Module \033[1;m"+"\n"+"\n"+"\033[1;32m3\033[1;m) \033[1;36m People Module \033[1;m"+"\n"+"\n"+"\033[1;32m4\033[1;m) \033[1;36m Exit \033[1;m"+"\n"+"\n"+"\033[1;32m-\033[1;m"*width+"\n"
# --------------------------------------------------------------------------------------- #
def People_module():
    os.system("clear")
    people_menu_text = "\033[1;36m People Module\033[1;m  "
    print "\033[1;32m-\033[1;m"*width+"\n"+print_text_center("%s")%(people_menu_text)+"\n"+"\033[1;32m-\033[1;m"*width+"\n"+"1) handshake"+"\n"+"2) Meeting"+"\n"+"\033[1;32m-\033[1;m"*width
# --------------------------------------------------------------------------------------- #
def menu_2_banner():
    os.system("clear")
    menu_2_text = "\033[1;36mBluetooth Module\033[1;m"
    print "\033[1;32m-\033[1;m"*width+print_text_center("%s")%(menu_2_text)+"\033[1;32m-\033[1;m"*width+"\n"+"\n"+"1) \033[1;36mRecon\033[1;m"+"\n"+"\n"+"2) \033[1;36mBack\033[1;m"+"\n"+"\n"+"3) \033[1;36mExit\033[1;m"+"\n"
# --------------------------------------------------------------------------------------- #
def menu1sub1():
    os.system("clear")
    thetext = "\033[1;36m  Wifi Module\033[1;m   "
    print "\033[1;32m-\033[1;m"*width+"\n"+print_text_center("%s")%(thetext)+"\n"+"\033[1;32m-\033[1;m"*width+"\n"+"\n"+"1) \033[1;36mTrack Device\033[1;m"+"\n"+"\n"+"2) \033[1;36mScan for Devices\033[1;m"+"\n"+"\n"+"3) \033[1;36mProximity Scanner\033[1;m"+"\n"+"\n"+"4) \033[1;36mExit\033[1;m"+"\n"+"\033[1;32m-\033[1;m"*width+"\n"
# --------------------------------------------------------------------------------------- #
def help_menu():
	os.system("clear")
	menu1()
# --------------------------------------------------------------------------------------- #
# ------------------- End Menu Banners -------------------------------------------------- #
# --------------------------------------------------------------------------------------- #
# ------------------- Start Wifi Tracking ----------------------------------------------- #
def do_track():
    ifacename = raw_input("Interface name:>")
    SUBJECT = raw_input("what is their mac:") 
    PROBE_REQUEST_TYPE=0
    PROBE_REQUEST_SUBTYPE=4
    os.system("clear")
    def PacketHandler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE and ( pkt.addr2.lower() in WHITELIST or pkt.addr2.upper() in WHITELIST):
                PrintPacket(pkt)
    def PrintPacket(pkt):
        try:
            extra = pkt.notdecoded
        except:
            extra = None
        if extra!=None:
            signal_strength = -(256-ord(extra[-4:-3]))
        else:
            signal_strength = -100
            print "No signal strength found"
        os.system("clear")
        print "\033[1;36m-\033[1;m"*width+"\n"+'\033[1;32mProbe Request Captured:\033[1;m'.center(termwidth)+"\n"+"\033[1;36m-\033[1;m"*width+"\n"+"\n"+("Source: \033[1;36m%s\033[1;m"%(pkt.addr2)).center(termwidth)+"\n"+("SSID: \033[1;36m%s\033[1;m"%(pkt.getlayer(Dot11ProbeReq).info)).center(termwidth)+"\n"+("RSSI: \033[1;36m%d\033[1;m"%(signal_strength)).center(termwidth)+"\n"+"\n"+("Target is \033[1;36m%s\033[1;m feet away"%(math.pow(10, (27.55 - (20 * math.log10(2457)) + math.fabs(signal_strength)) / 20.0) * 3.2808)).center(termwidth)+"\n"+"\n"+'\033[1;32m-\033[1;m'*width
    def track_main():
        os.system("clear")
        print "\033[1;32m-\033[1;m"*width+"\n"+"\n"+"[%s] Starting scan"%datetime.now()+"\n"+"\n"+'\033[1;36m-\033[1;m'*width+"\n"+"\n"+"Scanning for:"+"\n"+"\n"+"\n".join(mac for mac in WHITELIST)+"\n"+"\n"+'\033[1;36m-\033[1;m'*width+"\n"+"\n"+'\033[1;36m#\033[1;m'*width
        sniff(iface=ifacename,prn=PacketHandler)
    WHITELIST = [SUBJECT] 
    track_main()
# ------------------------------------------------------------------------------------------------------- #
def do_wifiscan():
    interface = raw_input("interface:>")
    os.system("clear")
    observedclients = []
    print '\033[1;36m-\033[1;m'*width
    def sniffmgmt(p):
        stamgmtstypes = (0, 2, 4)

        if p.haslayer(Dot11):
            if p.type == 0 and p.subtype in stamgmtstypes:
                if p.addr2 not in observedclients:
                    print (p.addr2).center(termwidth)
                    observedclients.append(p.addr2)
                if p.info not in observedclients:
                    print (p.info).center(termwidth)
                    observedclients.append(p.info)
                    print '\033[1;36m-\033[1;m'*width
    sniff(iface=interface, prn=sniffmgmt)
# ------------------------------------------------------------------------------------------------------- #
# ----------- Begin Proximity Command --------------------------------------------------- #  
def do_proximity():
    getifacen = raw_input('Interface:>')
    IFACE = getifacen
    maclist1 = raw_input('mac:>')
    MAC_LIST = [
        maclist1,
        #'XX:XX:XX:XX:XX:XX',
        ]

    MAC_LIST = [x.lower() for x in MAC_LIST]
    LOG_TYPES = {
        0: 'messages',
        1: 'probes',
    }
    MESSAGE_LEVELS = {
        0: 'INFO',
        1: 'ERROR',
        2: 'ALERT',
        }
    def to_unicode(obj, encoding='utf-8'):
        if isinstance(obj, basestring):
            if not isinstance(obj, unicode):
                obj = unicode(obj, encoding)
        return obj
    def log(log_type, values):
        values = (str(datetime.now()),) + values
        values = tuple([to_unicode(x) for x in values])
        values_str = ','.join('?'*len(values))
        query = 'INSERT INTO %s VALUES (%s)' % (LOG_TYPES[log_type], values_str)
        cur.execute(query, values)
        conn.commit()
    def log_message(level, message):
        log(0, (MESSAGE_LEVELS[level], message))
    def log_probe(bssid, rssi, essid):
        oui = resolve_oui(bssid)
        log(1, (bssid, rssi, essid, oui))
    def is_admin_oui(mac):
        return int(mac.split(':')[0], 16) & 2
    def resolve_oui(mac):
        if mac not in ouis:
            if is_admin_oui(mac):
                ouis[mac] = ADMIN_OUI
            else:
                try:
                    sadfacecontext = ssl.create_default_context()
                    sadfacecontext.check_hostname = False
                    sadfacecontext.verify_mode = ssl.CERT_NONE
                    resp = urllib2.urlopen('https://www.macvendorlookup.com/api/v2/%s' % mac,context=sadfacecontext)
                    if resp.code == 204:
                        ouis[mac] = 'Unknown'
                    elif resp.code == 200:
                        jsonobj = json.load(resp)
                        ouis[mac] = jsonobj[0]['company']
                    else:
                        raise Exception('Invalid response code: %d' % (resp.code))
                    log_message(0, 'OUI resolved. [%s => %s]' % (mac, ouis[mac]))
                except Exception as e:
                    log_message(1, 'OUI resolution failed. [%s => %s]' % (mac, str(e)))
                    return 'Error'
        return ouis[mac]
    def call_alerts(**kwargs):
        for var in globals():
            if var.startswith('ALERT_') and globals()[var] == True:
                if var.lower() in globals():
                    func = globals()[var.lower()]
                    try:
                        func(**kwargs)
                        log_message(2, '%s alert triggered. [%s]' % (var[6:], kwargs['bssid']))
                    except:
                        if DEBUG: print traceback.format_exc()
                        log_message(1, '%s alert failed. [%s]' % (var[6:], kwargs['bssid']))
    def packet_handler(pkt):
        rtlen = struct.unpack('h', pkt[2:4])[0]
        ftype = (ord(pkt[rtlen]) >> 2) & 3
        stype = ord(pkt[rtlen]) >> 4
        if ftype == 0 and stype == 4:
            rtap = pkt[:rtlen]
            frame = pkt[rtlen:]
            bssid = frame[10:16].encode('hex')
            bssid = ':'.join([bssid[x:x+2] for x in xrange(0, len(bssid), 2)])
            rssi = struct.unpack("b",rtap[-4:-3])[0]
            essid = frame[26:26+ord(frame[25])] if ord(frame[25]) > 0 else '<None>'
            data = (bssid, rssi, essid)
            foreign = True
            if bssid not in MAC_LIST:
                foreign = False
            if is_admin_oui(bssid) and ADMIN_IGNORE:
                foreign = False
            on_premises = False
            if rssi > RSSI_THRESHOLD:
                on_premises = True
            if LOG_LEVEL == 0: log_probe(*data)
            if foreign and LOG_LEVEL == 1: log_probe(*data)
            if on_premises and LOG_LEVEL == 2: log_probe(*data)
            if foreign and on_premises:
                if LOG_LEVEL == 3: log_probe(*data)
                if bssid not in alerts:
                    alerts[bssid] = datetime.now() - timedelta(minutes=5)
                if (datetime.now() - alerts[bssid]).seconds > ALERT_THRESHOLD:
                    if LOG_LEVEL == 4: log_probe(*data)
                    alerts[bssid] = datetime.now()
                    call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=resolve_oui(bssid))
    with sqlite3.connect(LOG_FILE) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute('CREATE TABLE IF NOT EXISTS probes (dtg TEXT, mac TEXT, rssi INT, ssid TEXT, oui TEXT)')
            cur.execute('CREATE TABLE IF NOT EXISTS messages (dtg TEXT, lvl TEXT, msg TEXT)')
            conn.commit()
            log_message(0, 'Proximity started.')
            cap = pcapy.open_live(IFACE, 1514, 1, 0)
            alerts = {}
            ouis = {}
            while True:
                try:
                    (header, pkt) = cap.next()
                    if cap.datalink() == 0x7F:
                        packet_handler(pkt)
                except KeyboardInterrupt:
                    break
                except:
                    if DEBUG: print traceback.format_exec()
                    continue
            log_message(0, 'Proximity stopped.')
# --------------------------------------------------------------------------------------- # 
# ----------- End Proximity Command ----------------------------------------------------- #
# ------------------------ End Wifi Tracking ------------------------------------------------------------ #
# ------------------ Start Bluetooth Tracking ----------------------------------------------------------- #
def btscanner():
    #clean up old files
    os.system("rm -rf data/devices.txt")
    os.system("rm -rf data/btaddresses.txt")
    print "\n"
    print "Finding Bluetooth Devices..."
    os.system("hcitool -i hci0 scan > data/devices.txt")
    print "Found The Following Devices:"
    os.system("cat data/devices.txt | grep -i '[0-9A-F]\{2\}\(:[0-9A-F]\{2\}\)\{5\}'")
    os.system("cat data/devices.txt | grep -o '[0-9A-F]\{2\}\(:[0-9A-F]\{2\}\)\{5\}' > data/btaddresses.txt")
    b = open('data/btaddresses.txt')
    macs = b.readlines()
    b.close()
    print "\n"
    print "Starting Information Gathering"
    print "\n"
    for mac in macs:
        print (green("Information about %s" % mac))
        subprocess.call("hcitool name %s" % mac, shell=True)
        print "\n"
        subprocess.call("hcitool info %s" % mac, shell=True)
        print "\n"  
        subprocess.call("sdptool records %s" % mac, shell=True)
        print "\n"
        subprocess.call("sdptool browse %s" % mac, shell=True)  
        print "\n"
    print "\n"
# -------------------------------------------------------------------------------------------- #
# ---------------------- End Bluetooth Tracking ---------------------------------------------- #
# ------------------------- Start People Tracking -------------------------------------------- #
def do_shake():
    def shake_c():
        os.system("clear")
        shakev = raw_input("\033[1;32mHow many people in the room:\033[1;m")
        os.system("clear")
        print "\033[1;36m-\033[1;m"*width+"\n"+"\n"+"There were "+ str(int(shakev)*(int(shakev)-1)/2)+ " possible handshakes."+"\n"+"\n"+"\033[1;36m-\033[1;m"*width
    shake_c()
# ------------------------------------------------------------------------------------------- #
def do_meet():  
    def prog():
        os.system("clear")
        print "\033[1;32m-\033[1;m"*width+"\n"+"Calculations are based on a one hour timeframe".center(termwidth)+"\n"+"Using the following Equation".center(termwidth)+"\n"+"\033[1;36mw1w2 + w1w3 + w2w3 - 1/2(w1w2^2 + w1w3^2 + w2w3^2) - 1/3(w1^3) - 1/6(w2^3)\033[1;m".center(termwidth)+"\n"+"\033[1;32m-\033[1;m"*width+"\n"
        w1 = (Fraction(str(Fraction(float(raw_input('How many minutes was Person 1 there'+ '\033[1;36m::\033[1;m\033[1;32m>\033[1;m'))/60).limit_denominator())))
        w2 = (Fraction(str(Fraction(float(raw_input('How many minutes was Person 2 there'+ '\033[1;36m::\033[1;m\033[1;32m>\033[1;m'))/60).limit_denominator())))
        w3 = (Fraction(str(Fraction(float(raw_input('How many minutes was Person 3 there'+ '\033[1;36m::\033[1;m\033[1;32m>\033[1;m'))/60).limit_denominator())))
        def floored_precentage(val, digits):
            val *= 10 ** (digits + 2)
            return '{1:.{0}f}%'.format(digits, floor(val) / 10 ** digits)
        os.system("clear")
        print "There is a "+ floored_precentage((w1*w2+w1*w3+w2*w3-(Fraction(1,2))*(w1*math.pow(w2,2)+w1*math.pow(w3,2)+w2*math.pow(w3,2))-(Fraction(1,3))*math.pow(w1,3)-(Fraction(1,6))*math.pow(w2,3)), 1) + " chance of all "+ '\033[1;32m3\033[1;m' +" People meeting."+"\n"+"\n"+"There is a "+ floored_precentage((w1+w2-((Fraction(w1,2))/2)-(math.pow(w2,2)/2)), 1) + " Chance of persons "+'\033[1;32m1\033[1;m'+ " and "+ '\033[1;32m2\033[1;m'+ " meeting."+"\n"+"\n"+"There is a "+ floored_precentage((w1+w3-((Fraction(w1,2))/2)-(math.pow(w3,2)/2)), 1) + " Chance of persons "+'\033[1;32m1\033[1;m'+" and "+'\033[1;32m3\033[1;m'+ " meeting."+"\n"+"\n"+"There is a "+ floored_precentage((w2+w3-(math.pow(w2,2)/2)-(math.pow(w3,2)/2)), 1) + " Chance of persons "+'\033[1;32m2\033[1;m'+ " and "+'\033[1;32m3\033[1;m'+ " meeting."    
    prog() 
# ------------------------ End People Tracking ---------------------------------------------- #