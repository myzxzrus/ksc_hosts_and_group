from typing import Union

import requests
import base64
import json
import urllib3


class RequiredAttrsMissingError(Exception):
    def __init__(self, attr_name):
        self.message = f'Required attribute "{attr_name}" not passed'

    def __str__(self):
        return repr(self.message)


class AuthenticationFailedError(Exception):
    def __init__(self):
        self.message = f'Authentication failed'

    def __str__(self):
        return repr(self.message)


def get_data(name: str, kwargs: dict):
    if name in kwargs:
        return kwargs[name]
    else:
        raise RequiredAttrsMissingError(name)


def convert_base64(text: str, encode: str = 'utf-8', decode: str = 'utf-8'):
    return base64.b64encode(text.encode(encode)).decode(decode)


class KSCHosts:
    """
    Получение списка хостов и групg из Kaspersky Security Center API. \n
    Обязательные именованные параметры: \n
        :ksc_server: str \n
        :user: str \n
        :password: str \n
    Необязательные атрибуты: \n
        :port: int По умолчанию 13299 \n
        :url: str По умолчанию {ksc_server}:{port}/api/v1.0 \n

    Публичные методы:
        get_group() - Получение списка групп
        get_hosts() - Получение списка хостов
    """

    def __init__(self, **kwargs):
        self.ksc_server = get_data('ksc_server', kwargs)
        self.port = kwargs.get('port', 13299)
        self.url = kwargs.get('url',
                              f'{self.ksc_server}:{self.port}/api/v1.0')
        self.user = convert_base64(get_data('user', kwargs))
        self.password = convert_base64(get_data('password', kwargs))
        self.headers = {
            'Authorization': f'KSCBasic user="{self.user}", pass="{self.password}", internal = "1"',
            'Content-Type': 'application/json',
        }
        self.session = requests.Session()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.auth_headers = {
            'Authorization': 'KSCBasic user="' + self.user + '", pass="'
                             + self.password + '", internal="1"',
            'Content-Type': 'application/json',
        }
        self._authentication()

    def _authentication(self):
        response = self.session.post(url=f'{self.url}/login',
                                     headers=self.auth_headers, data={}, verify=False)
        if response.status_code == 200:
            return True
        else:
            raise AuthenticationFailedError

    def _get_str_accessor(self) -> str:
        """
        :return: str
        """
        url = f'{self.url}/HostGroup.FindGroups'
        common_headers = {
            'Content-Type': 'application/json',
        }
        data = {"wstrFilter": "", "vecFieldsToReturn": ['id', 'name'],
                "lMaxLifeTime": 100}
        response = self.session.post(url=url, headers=common_headers,
                                     data=json.dumps(data), verify=False)
        strAccessor = json.loads(response.text)['strAccessor']
        return strAccessor

    def _get_items(self, str_accessor) -> list:
        """
        :param str_accessor:
        :return: list
        """
        url = f'{self.url}/ChunkAccessor.GetItemsCount'
        common_headers = {
            'Content-Type': 'application/json',
        }
        data = {"strAccessor": str_accessor}
        response = self.session.post(url=url, headers=common_headers,
                                     data=json.dumps(data), verify=False)
        items_count = json.loads(response.text)['PxgRetVal']
        start = 0
        step = 100000
        results = list()
        while start < items_count:
            url = f'{self.url}/ChunkAccessor.GetItemsChunk'
            data = {"strAccessor": str_accessor, "nStart": 0, "nCount":
                items_count}
            response = self.session.post(url=url,
                                         headers=common_headers, data=json.dumps(data), verify=False)
            results += json.loads(response.text)['pChunk']['KLCSP_ITERATOR_ARRAY']
            start += step
        return results


    def get_group(self) -> list:
        """
        Возвращает список групп.
        :return: list
        """
        str_accessor = self._get_str_accessor()
        return self._get_items(str_accessor)


    def get_hosts(self, **kwargs) -> list:
        """
        Возвращает список хостов \n
        Принимает необязательный именованный параметр group_id, для поиска по определенной группе,
        иначе будет выполнен поиск по всем группам.

        :param kwargs:
        :return:
        """
        hosts_list = []
        if 'group_id' in kwargs:
            groups = [{'value': {'id': kwargs['group_id']}}]
        else:
            groups = self.get_group()
        for group in groups:
            group_id = group['value']['id']
            url = f'{self.url}/HostGroup.FindHosts'
            common_headers = {
                'Content-Type': 'application/json',
            }
            data = {"wstrFilter": "(KLHST_WKS_GROUPID = " +
                                  str(group_id) + ")",
                    "vecFieldsToReturn": ['KLHST_WKS_FQDN',
                                          'KLHST_WKS_HOSTNAME'], "lMaxLifeTime": 100}
            response = self.session.post(url=url,
                                         headers=common_headers, data=json.dumps(data), verify=False)
            if 'strAccessor' in json.loads(response.text):
                str_accessor = json.loads(response.text)['strAccessor']
                hosts = self._get_items(str_accessor)
                hosts_list = hosts_list + hosts
        return hosts_list


