# -*- coding: utf-8 -*-
# @Author  : nJcx
# @Email   : njcx86@gmail.com

from elasticsearch import Elasticsearch
from settings import es_ip, es_port, ip_list
from utils import Logger
import xmltodict
import os
import threading
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
        logger.error(str(e))
        return {}


def json_to_es(index, json_):

    try:
        es.index(index=index, doc_type="vuln", body=json_)
    except Exception as e:
        logger.error(str(e))


def masscan_scan(ip):

    try:
        if ip:
            os.system('masscan --ping {0} --rate 1000   -oL {1}.txt'.format(ip, ip.split('/')[0]))
    except Exception as e:
        logger.error(str(e))


def nmap_scan(ip):
    try:
        if ip:
            os.system('nmap -T5 -Pn -A -oX {0}.xml {1}'.format(ip, ip))
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
        print("目录创建成功！")
    cmd = """awk '{print $4}' *.txt | tr -s '\n' > alive_host/host.txt """
    os.system(cmd)
    os.system("""rm -f *.txt""")


def nmap_scan_worker():

    t_obj = []
    for i in range(len(ip_list)):
        t = threading.Thread(target=masscan_scan, args=(ip_list[i],))
        t_obj.append(t)
        t.start()
    for t in t_obj:
        t.join()


if __name__ == '__main__':
    json_ = xml_to_json('test/test.xml')

    print json_
    masscan_scan_worker()


    # json_to_es('nmap-es', json_)
    # del json_['nmaprun']['scaninfo']
    # del json_['nmaprun']['taskbegin']
    # del json_['nmaprun']['taskend']
    #
    #
    # # # print json_
    # json_to_es('nmap-es', json_)




