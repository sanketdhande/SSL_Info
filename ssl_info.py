from urllib.request import ssl, socket
from csv import DictWriter
import timeout_decorator


def write_file(data, field_names):
    with open('ssl_data.csv', 'a') as fp:
        dictwriter_object = DictWriter(fp, fieldnames=field_names)
        dictwriter_object.writerow(data)
        fp.close()


@timeout_decorator.timeout(5)
def create_connection(base_url):
    port = '443'
    hostname = base_url
    context = ssl.create_default_context()
    sock = socket.create_connection((hostname, port))
    ssock = context.wrap_socket(sock, server_hostname=hostname)
    return sock, ssock


def get_certificate(base_url):
    data = {'notAfter': None, 'notBefore': None, 'commonName': None, 'Error': None, 'base_url': None}
    field_names = [data.keys()][0]
    try:
        sock, ssock = create_connection(base_url)
        notAfter = ssock.getpeercert()["notAfter"]
        notAfter = notAfter.replace(notAfter.split()[2], "")
        notAfter = " ".join(notAfter.split()[0:-1])
        data['notAfter'] = notAfter
        notBefore = ssock.getpeercert()["notBefore"]
        notBefore = notBefore.replace(notBefore.split()[2], "")
        notBefore = " ".join(notBefore.split()[0:-1])
        data['notBefore'] = notBefore
        for i in ssock.getpeercert()["subject"]:
            if "commonName" in i[0]:
                commonName = i[0][1]
                data['commonName'] = commonName

        write_file(data, field_names)

    except Exception as e:
        data['Error'] = 'Expired'
        data['base_url'] = base_url
        write_file(data, field_names)
        print(e.__str__())


def readfile():
    with open('domains.txt', 'r') as file:
        row = file.readlines()
        for url in row:
            print(url)
            url = url.rstrip()
            get_certificate(url)


readfile()
