# ksc_hosts_and_group
Getting a list of hosts and groups from Kaspersky Security Center

Template:

```python
from ksc_host_and_group import KSCHosts


if __name__ == '__main__':
    t = KSCHosts(ksc_server="https://10.2.111.88", user='test_user', password='888888')
    group = t.get_group()
    print(group)

    #  Получение всех хостов по всем группам.
    hosts = t.get_hosts()
    print(hosts)

    #  Получение хостов по определенной группе. Необходимо передать group_id
    hosts = t.get_hosts(group_id=0)
    print(hosts)
```
