# -*- coding: utf-8 -*-
# @Author  : nJcx
# @Email   : njcx86@gmail.com

from elasticsearch import Elasticsearch
from settings import es_ip, es_port
from utils import Logger
import json
import xmltodict
import os
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


if __name__ == '__main__':
    json_ = xml_to_json('test.xml')

    print json_

    # json_to_es('nmap-es', json_)
    # del json_['nmaprun']['scaninfo']
    # del json_['nmaprun']['taskbegin']
    # del json_['nmaprun']['taskend']
    #
    #
    # # # print json_
    # json_to_es('nmap-es', json_)
