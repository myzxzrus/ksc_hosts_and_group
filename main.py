from ksc_host_and_group import KSCHosts


if __name__ == '__main__':
    t = KSCHosts(ksc_server="https://10.2.111.88", user='test_user', password='888888')
    group = t.get_group()
    print(group)
    hosts = t.get_hosts(0)
    print(hosts)