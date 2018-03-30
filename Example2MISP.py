#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
import csv
from IPy import IP
import sys
import os
import validators


# distribution
distribution_your_organisation_only='0'
distribution_this_community_only='1'
distribution_connected_communities='2'
distribution_all_communities='3'
# threat_level_id
threat_level_id_high='1'
threat_level_id_medium='2'
threat_level_id_low='3'
# analysis
analysis_initial='0'
analysis_ongoing='1'
analysis_completed='2'


# *** MISP misp.organizacion.com ***
misp_url = 'https://misp.organizacion.com/'
misp_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
misp_cert = None
misp_verifycert = False


def connect(url, key, verifycert, cer):
    try:
        misp = PyMISP(url, key, verifycert, 'json', cert=cer)
        return misp
    except Exception as e:
        print('Unable to connect to MISP: %s' % e)
        exit(1)


def check_IP(ip):
    try:
        IP(ip)
        return True
    except ValueError:
        return False


def check_email(url):
    return validators.email(url)


def check_URL(url):
    return validators.url(url)


def add_tags(misp, event, type, subtype):
    # Se añaden las etiquetas por tipo
    if type == 'Trojan':
        misp.tag(event['Event']['uuid'], 'circl:incident-classification=\"malware\"')
    elif type == 'Phishing':
        misp.tag(event['Event']['uuid'], 'circl:incident-classification=\"phishing\"')
    # Se añaden las etiquetas por subtipo
    if subtype == 'Trickbot / Trickster':
        misp.tag(event['Event']['uuid'], 'misp-galaxy:banker=\"Trickbot\"')
    elif subtype == "Dyre":
        misp.tag(event['Event']['uuid'], 'misp-galaxy:banker=\"Dyre\"')
    elif subtype == "Dridex":
        misp.tag(event['Event']['uuid'], 'misp-galaxy:banker=\"Dridex\"')
    elif subtype == "SpyEye":
        misp.tag(event['Event']['uuid'], 'misp-galaxy:banker=\"SpyEye\"')
    elif subtype == "Tinba":
        misp.tag(event['Event']['uuid'], 'misp-galaxy:banker=\"Tinba\"')
    elif subtype == "Zeus":
        misp.tag(event['Event']['uuid'], 'misp-galaxy:banker=\"Zeus\"')
    elif subtype == "Ransomware":
        misp.tag(event['Event']['uuid'], 'malware_classification:malware-category=\"Ransomware\"')
    elif subtype == "Fugas de información" or subtype == "Data Leak":
        misp.tag(event['Event']['uuid'], 'circl:incident-classification=\"information-leak\"')
    elif subtype == "Aplicación Móvil Maliciosa":
        misp.tag(event['Event']['uuid'], 'misp-galaxy:android=\"Fakeapp\"')


def get_event(misp, reg, info, date):
    # Se crea un nuevo evento a distribuir entre todas las comunidades del MISP, con nivel bajo, como analisis completado y publicado
    event = misp.new_event(distribution=distribution_all_communities, threat_level_id=threat_level_id_low, analysis=analysis_completed, info=info, date=date, published=True)
    print('Se ha creado el evento', event['Event']['id'])
    return event


def process_file(file_name):
    # Se abre el fichero
    file = open(file_name, 'r', encoding='latin-1')
    # Se inicializa el contador de eventos a tratar
    i = 0
    # Se establece la conexion con el MISP
    misp = connect(misp_url, misp_key, misp_verifycert, misp_cert)
    # Se pone un bucle que lee cada registro que hay en el fichero CSV con campos separados por un punto y coma (;)
    for reg in csv.DictReader(file, delimiter=';'):
        # Se crea el registro con titulo Tipo + Subtipo de ataque, y la fecha del registro
        event = get_event(misp, reg, reg['Tipo'] + ' - '+ reg['Subtipo'], reg['Fecha de registro'])
        # Se crea un bucle para tratar todas las URLs separadas por un pipe (|) añadiendolas como atributos
        for url in reg['Urls'].split(' | '):
            # Se verifica que sea un email
            if check_email(url):
                misp.add_named_attribute(event, 'email-dst', url, category='Network activity', to_ids=True, distribution=distribution_all_communities)
            # Se verifica que sea una URL
            elif check_URL(url):
                misp.add_named_attribute(event, 'url',  url, category='Network activity', to_ids=True, distribution=distribution_all_communities)
        # Se crea un bucle para tratar todos los dominios e IPs separados por un pipe (|) añadiendolos como atributos
        for ip in reg['Dominios-IPs'].split(' | '):
            # Se verifica que sea una IP
            if check_IP(ip):
                misp.add_named_attribute(event, 'ip-dst', ip, category='Network activity', to_ids=True, distribution=distribution_all_communities)
            # Si no es una IP, se asume que es un dominio
            else:
                misp.add_named_attribute(event, 'domain', ip, category='Network activity', to_ids=True, distribution=distribution_all_communities)
        # Se crea un atributo con el HASH
        if 'Hash' in reg and reg['Hash'] != '':
            misp.add_named_attribute(event, 'md5', reg['Hash'], category='Payload delivery', comment=None, to_ids=False, distribution=distribution_all_communities)
        # Se crea un atributo, que no se comparte con otras organizaciones, para el Id interno
        if 'Id' in reg and reg['Id'] != '':
            misp.add_named_attribute(event, 'text', 'Id: ' + reg['Id'], category='Other', comment=None, to_ids=False, distribution=distribution_your_organisation_only)
        # Se crea un atributo, que no se comparte con otras organizaciones, con el ISP
        if 'ISPs' in reg and reg['ISPs'] != '':
            misp.add_named_attribute(event, 'text', 'ISPs: ' + reg['ISPs'], category='Other', comment=None, to_ids=False, distribution=distribution_your_organisation_only)
        # Se añaden las etiquetas que correspondan en base al tipo y subtipo de evento
        add_tags(misp, event, reg['Tipo'], reg['Subtipo'])
        # Se publica el evento
        misp.fast_publish(event['Event']['id'], alert=False)
        i = i + 1
    file.close()
    print()
    print(i, 'casos')


if __name__ == '__main__':
    # Se amplia el tamaño por defecto de registro (en casos con muchas URLs puede dar problemas)
    csv.field_size_limit(sys.maxsize)
    # Se procesa el fichero 'Example2MISP.csv' que tiene la estructura 'Id;Tipo;Subtipo;Urls;ISPs;Dominios-IPs;Hash;Fecha de registro;Fecha de cierre'
    process_file('Example2MISP.csv')
