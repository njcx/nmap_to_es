# -*- coding: utf-8 -*-
# @Author  : nJcx
# @Email   : njcx86@gmail.com

from elasticsearch import Elasticsearch
import xmltodict
import json
es_ip = "10.10.116.177"
es_port = 9201

es = Elasticsearch([{'host': es_ip, 'port': es_port}])


x = ''
xxx = json.dumps(xmltodict.parse(x), indent=4)

es.index(index = "nmap-es", doc_type="vuln", body=xxx)