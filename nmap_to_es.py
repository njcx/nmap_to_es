# -*- coding: utf-8 -*-
# @Author  : nJcx
# @Email   : njcx86@gmail.com

from elasticsearch import Elasticsearch
import xmltodict
import json


es_ip = "10.10.116.177"
es_port = 9201
es = Elasticsearch([{'host': es_ip, 'port': es_port}])


def xml_to_json(path):
    try:
        with open(path, 'r') as load_f:
            temp_ = xmltodict.parse(load_f).get("nmaprun")
            return {key: temp_[key]
                    for key in temp_
                    if key not in ["verbose", 'scaninfo', 'taskbegin', 'taskend', "debugging"]}

    except Exception as e:
        print(e)
        return {}


def json_to_es(index, json_):

    try:
        es.index(index=index, doc_type="vuln", body=json_)

    except Exception as e:
        print(e)
        return {}


if __name__ == '__main__':
    json_ = xml_to_json('test.xml')

    print json_

    # json_to_es('nmap-es', json_)
    # del json_['nmaprun']['scaninfo']
    # del json_['nmaprun']['taskbegin']
    # del json_['nmaprun']['taskend']
    #
    #
    # # print json_
    json_to_es('nmap-es', json.dumps(json_))
