# -*- coding: utf-8 -*-
# @Author  : nJcx
# @Email   : njcx86@gmail.com

from elasticsearch import Elasticsearch
from settings import es_ip, es_port, ip_list
from utils import Logger
import xmltodict
import os
import threading
import time
import json

logger = Logger.get_logger(__name__, path=os.getcwd())
es = Elasticsearch([{'host': es_ip, 'port': es_port}])


def xml_to_json(path):
    try:
        with open(path, 'r') as load_f:
            temp_ = xmltodict.parse(load_f).get("nmaprun")
            return {key: temp_[key]
                    for key in temp_
                    if key not in ["verbose", 'scaninfo', 'taskbegin', 'taskend', "debugging"]}

    except Exception as e:
        logger.error(str(e)+path)
        return {}


def json_to_es(index, json_):
    try:
        es.index(index=index, doc_type="vuln", body=json_)
    except Exception as e:
        try:
            es.index(index=index + '_', doc_type="vuln", body=json.dumps(json_))
        except Exception as e:
            es.index(index=index + '__', doc_type="vuln", body=json.dumps(json_))
            pass


def masscan_scan(ip):
    try:
        if ip:
            if not os.path.exists('tmp'):
                os.makedirs('tmp')
            os.system('masscan --ping {0} --rate 1000 -oL tmp/{1}.txt'.format(ip, ip.split('/')[0]))
    except Exception as e:
        logger.error(str(e))


def nmap_scan(ip):
    try:
        if ip:
            if not os.path.exists('report'):
                os.makedirs('report')
            os.system('nmap -sV -Pn -A -T5 --script=nmap-vulners/vulners.nse -oX report/{0}.xml {1}'.format(ip, ip))
    except Exception as e:
        logger.error(str(e))


def masscan_scan_worker():

    t_obj = []
    for i in range(len(ip_list)):
        t = threading.Thread(target=masscan_scan, args=(ip_list[i],))
        t_obj.append(t)
        t.start()
    for t in t_obj:
        t.join()
    if not os.path.exists('alive_host'):
        os.makedirs('alive_host')
    cmd = """ awk '{print $4}' tmp/*.txt | tr -s '\n' > alive_host/host.txt """
    os.system(cmd)
    os.system("""rm -f tmp/*.txt""")


def read_txt(path):
    lines = []
    try:
        with open(path, 'r') as file_to_read:
            while True:
                line = file_to_read.readline()
                if not line:
                    break
                line = line.strip('\n')
                lines.append(line)
    except Exception as e:
        logger.error(str(e))
    return lines


def nmap_scan_worker():
    lst = read_txt('alive_host/host.txt')
    tmp_ = [lst[i:i+5] for i in range(0, len(lst), 5)]
    print tmp_
    if tmp_:
        for list_ in tmp_:
            t_obj = []
            for i in range(len(list_)):
                t = threading.Thread(target=nmap_scan, args=(list_[i],))
                t_obj.append(t)
                t.start()
            for t in t_obj:
                t.join()


def nmap_to_es(index):
        if os.path.exists('report'):
            files = os.listdir('report')
        for file in files:
                json_to_es(index, xml_to_json('report'+'/'+file))
        os.system("""rm -f report/*.xml""")


if __name__ == '__main__':

    while True:
        now = time.strftime('%Y-%m-%d')
        masscan_scan_worker()
        nmap_scan_worker()
        es.indices.delete('nmap-*')
        nmap_to_es('nmap-' + now)





