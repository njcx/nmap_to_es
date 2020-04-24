# -*- coding: utf-8 -*-
# @Author  : nJcx
# @Email   : njcx86@gmail.com


from elasticsearch import Elasticsearch
from settings import es_ip, es_port
import xmltodict , json
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

        print json.dumps(json_.get('host').get('ports').get('port'))
        es.index(index=index, doc_type="vuln", body=json.dumps(json_))
    except Exception as e:
        print(e)


if __name__ == '__main__':
    json_ = xml_to_json('test.xml')
    json_to_es('test', json_)

    # print(json_)

