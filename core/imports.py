#!/usr/bin/python
# --------------------------------------------------------------------------------------- #

# -------------------------------------------------------------------------------------------------------------------------- #
#                     .g8888bgd 
#                   .dP       M 
# ,pP"Ybd  ,pW8Wq.  dM        ; 
# 8I      6W     Wb MM          
#  YMMMa. 8M     M8 MM.         
# L.   I8 YA.   ,A9  Mb.     , 
# M9mmmP;  .Ybmd9.    ..bmmmd.
# -------------------------------------------------------------------------------------------------------------------------- #
import os, sys, subprocess, time
import traceback, re, readline, math
from scapy.all import *
from contextlib import closing
from datetime import datetime, timedelta
import json, pcapy, sqlite3, struct, traceback
import urllib2, ssl
from math import floor
from fractions import Fraction
# --------------------------------------------------------------------------------------- #
import console
(width, height) = console.getTerminalSize()

termwidth = width 
fillchar = '*'

def print_text_center(text, ch='=', length=width):

    if text is None:
        return ch * length
    elif len(text) + 2 + len(ch)*2 > length:
        # Not enough space for even one line char (plus space) around text.
        return text
    else:
        remain = length - (len(text) + 16)
        prefix_len = remain / 2
        suffix_len = remain - prefix_len
        if len(ch) == 1:
            prefix = ch * prefix_len
            suffix = ch * suffix_len
        else:
            prefix = ch * (prefix_len/len(ch)) + ch[:prefix_len%len(ch)]
            suffix = ch * (suffix_len/len(ch)) + ch[:suffix_len%len(ch)]
        return prefix + ' ' + text + ' ' + suffix
fillchar2 = '#'
fillchar3 = '-'
# --------------------------------------------------------------------------------------- #
from email.mime.text import MIMEText
import smtplib
import urllib
# ------------------------------------------------------------------------------------------------------------------------------ #
# ----- End Imports ------------------------------------------------------------------------------------------------------------ #
# ------------------------------------------------------------------------------------------------------------------------------ #
# ------------------------------------------------------------------------------------------------------------------------------ #
# ----- Start Alerts ----------------------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------------------------------ #
# ------------------------------------------------------------------------------------------------------------------------------ #
# ----- Define SMS Alert ------------------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------------------------------ #
def alert_sms(**kwargs):
    msg = MIMEText('proximity alert! A foreign device (%s - %s) has been detected on the premises.' % (kwargs['bssid'], kwargs['oui']))
    server = smtplib.SMTP(SMTP_SERVER)
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    server.sendmail(SMTP_USERNAME, SMS_EMAIL, msg.as_string())
    server.quit()
# ------------------------------------------------------------------------------------------------------------------------------ #
# ----- Define Pushover Alert -------------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------------------------------ #
def alert_pushover(**kwargs):
    msg = 'Proximity alert! A foreign device (%s - %s) has been detected on the premises.' % (kwargs['bssid'], kwargs['oui'])
    url = 'https://api.pushover.net/1/messages.json'
    payload = {'token': PUSHOVER_API_KEY, 'user': PUSHOVER_USER_KEY, 'message': msg}
    payload = urllib.urlencode(payload)
    resp = urllib2.urlopen(url, data=payload)
# ------------------------------------------------------------------------------------------------------------------------------ #
# ----- Define Print Alert To Screen ------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------------------------------ #
def alert_printmessage(**kwargs):
    os.system('clear')
    tmess = '\033[1;36m#############################################\033[1;m'
    tmess2 = '\033[1;36m---------------------------------------------\033[1;m'
    timestamp = "%s"%datetime.now()
    ptime = (timestamp)
    print tmess
    print tmess2
    print """ 
    Proximity Alert! 
    """
    print """ 
    %s
    """%(ptime)
    print """
    A Pig (%s - %s) 
    has been detected around the premises.""" % (kwargs['bssid'], kwargs['oui'])
    print tmess2
    print tmess
# ------------------------------------------------------------------------------------------------------------------------------ #
# ----- End of Alerts ---------------------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------------------------------ #



def color(text, color_code):
	if sys.platform == "win32" and os.getenv("TERM") != "xterm":
	   return text

	   return '\x1b[%dm%s\x1b[0m' % (color_code, text)
def red(text):
	return color(text, 31)

def blink(text):
	return color(text, 5)

def green(text):
	return color(text, 32)

def blue(text):
	return color(text, 34)
# --------------------------------------------------------------------------------------- #
# --------------------------------------------------------------------------------------- #	
# ------------------------------------------------ #
# ----- Start Config ----------------------------- #
# ------------------------------------------------ #
ADMIN_OUI = 'Admin OUI'
ADMIN_IGNORE = False
# ------------------------------------------------ #
# ----- Set the RSSI Alert Threshold ------------- #
RSSI_THRESHOLD = -50
ALERT_THRESHOLD = 10
# ------------------------------------------------ #
# ----- Define what Database to log to ----------- #
LOG_FILE = 'data/log.db'
LOG_LEVEL = 3
DEBUG = True
# ------------------------------------------------ #
# ----- Which Alerts to use ---------------------- #
ALERT_SMS = False
ALERT_PUSHOVER = False
ALERT_PRINTMESSAGE = True
# ------------------------------------------------ #
# ----- Set Smtp and Pushover Alert Settings ----- #
SMTP_SERVER = ('smtp.gmail.com',587)
SMTP_USERNAME = 'email name'
SMTP_PASSWORD = 'email pass'
SMS_EMAIL = 'sms email (phone # @ carrier)'
PUSHOVER_API_KEY =  ' api key '
PUSHOVER_USER_KEY = ' user key '
# ------------------------------------------------ #
# ----- End Config ------------------------------- #
# ------------------------------------------------ #
