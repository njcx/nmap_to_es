# -*- coding: utf-8 -*-
# @Author  : nJcx
# @Email   : njcx86@gmail.com


from elasticsearch import Elasticsearch
from settings import es_ip, es_port
import xmltodict
from collections import OrderedDict
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

        for x in json_.get('host').get('ports').get('port'):
            if type(x.get('script')) == type([]):
                for x in x.get('script'):
                    if x.get('elem'):
                        if type(x.get('elem')) == type(OrderedDict()):
                            print x.get('elem')
                            print x
                            x.update(x.get('elem'))
                            x.pop('elem')
                            print x

        es.index(index=index, doc_type="vuln", body=json_)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    json_ = xml_to_json('test.xml')
    json_to_es('test', json_)

    # print(json_)

