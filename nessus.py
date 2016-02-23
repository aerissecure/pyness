"""
A module for interacting with a Nessus scanner
and pasing report results.

Parser for Nessus Report v2 XML.
"""
__version_info__ = ('3', '0')
__version__ = '.'.join(__version_info__)
__nessus_version__ = ('5', '2')

import datetime
import json
import logging
import requests
import socket
import time
import urlparse

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

logger = logging.getLogger('nessus')



class NessusError(Exception):
    """
    Base class for Nessus exceptions in this module
    """
    def __init__(self, ref='', code=None):
        self.ref = ref
        self.code = code

    def __str__(self):
        c = "Status Code %d" % self.code if self.code else ""
        r = self.ref if self.ref else ""
        if c and r:
            return repr(": ".join([c, r]))
        if c:
            return repr(c)
        if r:
            return repr(r)
        return repr("Unknown error")

# Nessus Scanner

class RESTConnection:

    """
    The class for Nessus connection objects. After instantiation you
    will be able to communicate with a nessus server.
    """

    def __init__(self, accesskey, secretkey, scanner_ip="127.0.0.1",
                 scanner_port=8834):
        self._accesskey = accesskey
        self._secretkey = secretkey
        self._scanner_ip = scanner_ip
        self._scanner_port = scanner_port
        self._scanner_socket = ('https://' + self._scanner_ip + ':' +
                                str(self._scanner_port))

    def raw_request(self, method, uri, data={}, json={}, verify=False):
        url = urlparse.urljoin(self._scanner_socket, uri)

        headers = {}
        keys = "accessKey=%s; secretKey=%s" % (self._accesskey, self._secretkey)
        headers['X-ApiKeys'] = keys
        headers['Content-Type'] = 'application/json'

        return requests.request(method, url, data=data, json=json,
                                headers=headers, verify=verify)

    def json_request(self, method, uri, data, verify=False):
        """
        Send request to Nessus and return the
        python object of the reply data.
        """

        reply = self.raw_request(method, uri, json=data, verify=verify)

        code = reply.status_code
        try:
            # ensure body has json
            cont = reply.json()
            if code != 200:
                # assume there is an error json if request unsuccessful
                raise NessusError(cont['error'], code)
        except NessusError:
            raise
        # except Exception, e:
        #     raise NessusError(repr(e), code)

        return cont

    def session_get(self, method='GET'):
        """
        {"error":"You need to log in to perform this request"}
        else
        {"username": "jstiles", "id": 2, ...}
        """
        uri = 'session'
        data = {}
        cont = self.json_request(method, uri, data)
        return cont

    def creds_ok(self):
        try:
            self.session_get()
            return True
        except:
            return False

    def server_status(self, method='GET'):
        """
        Returns the Nessus server status.

        keys:
        progress
        status
        """
        uri = 'server/status'
        data = {}
        cont = self.json_request(method, uri, data)
        return cont

    def server_properties(self, method='GET'):
        """
        Returns the Nessus server properties.

        keys:
        capabilities
        enterprise
        expiration
        expiration_time
        feed
        idle_timeout
        loaded_plugin_set
        login_banner
        nessus_type
        nessus_ui_version
        notifications[]
        plugin_set
        scanner_boottime
        server_uuid
        server_version
        """
        uri = 'server/properties'
        data = {}
        cont = self.json_request(method, uri, data)
        return cont

    def wait_download(self, scan_id):
        """
        Export scan, wait for download to become available,
        then download the scan.
        """
        file_id = self.scans_export(scan_id)['file']
        while self.scans_export_status(scan_id, file_id)['status'] == 'loading':
            time.sleep(1)
        # {'status': 'ready'}
        return self.scans_download(scan_id, file_id)

    def scans_download(self, scan_id, file_id, method='GET'):
        """
        Export the given scan.
        """
        uri = 'scans/{scan_id}/export/{file_id}/download'
        uri = uri.format(scan_id=scan_id, file_id=file_id)
        data = {}
        cont = self.raw_request(method, uri, data=data).content
        return cont

    def scans_export(self, scan_id, format='nessus', method='POST'):
        """
        Download an exported scan.

        keys:
        file
        """
        uri = 'scans/{scan_id}/export'.format(scan_id=scan_id)
        data = {'format':format}
        cont = self.json_request(method, uri, data)
        return cont

    def scans_export_status(self, scan_id, file_id, method='GET'):
        """
        Export the given scan.

        keys:
        file
        """
        uri = 'scans/{scan_id}/export/{file_id}/status'
        uri = uri.format(scan_id=scan_id, file_id=file_id)
        data = {}
        cont = self.json_request(method, uri, data)
        return cont

    def scans_details(self, scan_id, method='GET'):
        """
        Returns details for the given scan.

        keys:
        info
            edit_allowed
            status
            policy
            pci-can-upload
            hasaudittrail
            scan_start
            folder_id
            targets
            timestamp
            object_id
            scanner_name
            haskb
            uuid
            hostcount
            scan_end
            name
            user_permissions
            control
        hosts[]
        comphosts[]
        notes[]
        remediations
        vulnerabilities[]
        compliance[]
        history[]
        filters[]
        """
        uri = 'scans/{scan_id}'.format(scan_id=scan_id)
        data = {}
        cont = self.json_request(method, uri, data)
        return cont

    def scans(self, method='GET'):
        """
        Returns the scan list.

        return:
        [{scan},{scan},...]

        keys:
        folders[]
        scans[]
            control
            creation_date
            folder_id
            id
            last_modification_date
            name
            owner
            read
            rrules
            shared
            starttime
            status
            timezone
            user_permissions
            uuid
        timestamp
        """
        uri = 'scans'
        data = {}
        cont = self.json_request(method, uri, data)
        return cont

    def scan_id(self, name):
        """
        Convert a scan name into an id
        """
        for scan in self.scans()['scans']:
            if scan['name'] == str(name):
                return scan['id']
        return None


class NessusScan:
    """
    A Scan class for interfacing with Nessus.

    Used to add additional error handling for scripts that require
    scan interaction.
    """

    def __init__(self, rest_connection, scan_uuid):
        self.conn = rest_connection
        self.scan_uuid = scan_uuid

    def scan_status(self):
        """Return status of the scan."""
        return self.conn.scan_status(self.scan_uuid)

    def active(self):
        """True if scan is currently taking place."""
        return self.conn.scan_active(self.scan_uuid)

    # def progress(self):
        # """Return percent complete as an int."""
        # return self.nxmlrpc.scan_progress(self.uuid)[0]

    def wait_until_completed(self):
        """
        Wait until scan completes, then return elapsed time in seconds.
        """
        start = time.time()
        while True:
            if self.scan_status() == u'completed':
                break
            time.sleep(10)
        return time.time() - start





# Nessus Report Parser

STRP_STRING = '%a %b %d %H:%M:%S %Y'
STRP_DATE = '%Y/%m/%d'

class Item(object):
    """Equivalent to the <ReportItem> tag."""
    def __init__(self, etree):
        self.etree = etree
        self._parse()

    def __repr__(self):
        return '<Item: %s[%s] %s>' % (self.protocol, self.port,
                                      self.plugin_name)

    def _parse(self):
        self.port = int(self.etree.attrib.get('port'))
        self.protocol = self.etree.attrib.get('protocol')
        self.service = self.etree.attrib.get('svc_name')
        self.plugin_id = int(self.etree.attrib.get('pluginID'))
        self.plugin_name = self.etree.attrib.get('pluginName')
        self.plugin_family = self.etree.attrib.get('pluginFamily')
        # temporary dict for tags so we can use .get method
        tagdict = dict((el.tag, el.text) for el in self.etree.getchildren())
        self.plugin_version = tagdict.get('plugin_version')
        self.description = tagdict.get('description')
        self.synopsis = tagdict.get('synopsis')
        self.solution = tagdict.get('solution')
        self.plugin_output = tagdict.get('plugin_output', '').strip()
        self.cvss_base_score = tagdict.get('cvss_base_score')
        self.cvss_base_vector = tagdict.get('cvss_vector')
        self.vuln_publication_date = tagdict.get('vuln_publication_date')
        self.plugin_publication_date = tagdict.get('plugin_publication_date')
        self.plugin_modification_date = tagdict.get('plugin_modification_date')
        if self.vuln_publication_date:
            self.vuln_publication_date = datetime.datetime.strptime(
                    self.vuln_publication_date, STRP_DATE).date()
        if self.plugin_publication_date:
            self.plugin_publication_date = datetime.datetime.strptime(
                    self.plugin_publication_date, STRP_DATE).date()
        if self.plugin_modification_date:
            self.plugin_modification_date = datetime.datetime.strptime(
                    self.plugin_modification_date, STRP_DATE).date()
        # composite field of newest plugin date
        self.plugin_date = (self.plugin_modification_date or
                            self.plugin_publication_date)

        # parse single tag with multiple values
        self.cpes = []
        cpe = self.etree.find('cpe')
        if cpe is not None:
            self.cpes = cpe.text.split()
        # parese single tag with multiple instances
        self.cves = [el.text for el in self.etree.findall('cve')]

    @property
    def is_vuln(self):
        return True if self.plugin_id != 0 else False

    def todict(self):
        ##
        ## consider doing with a method that will display all attributes
        ##
        return {'port':self.port,
                'protocol':self.protocol,
                'service':self.service,
                'plugin_id':self.plugin_id,
                'plugin_name':self.plugin_name,
                'plugin_version':self.plugin_version,
                'description':self.description,
                'synopsis':self.synopsis,
                'plugin_output':self.plugin_output,
                'cvss_base_score':self.cvss_base_score,
                'cvss_base_vector': self.cvss_base_vector,
                'plugin_publication_date':self.plugin_publication_date,
                'vuln_publication_date':self.vuln_publication_date}


class Host(object):
    """Equivalent to the <ReportHost> and <HostProperties> tags."""
    def __init__(self, etree, timezone=None):
        self.etree = etree
        self.timezone = timezone
        self.items = []
        self._parse()

    def __repr__(self):
        return '<Host: %s>' % self.ip

    def _parse(self):
        self.target = self.etree.attrib['name']
        host_properties = self.etree.find('HostProperties')
        attrs = dict((tag.attrib['name'], tag.text) for tag in host_properties)
        self.start = attrs.get('HOST_START')
        self.startdt = datetime.datetime.strptime(self.start, STRP_STRING)
        self.end = attrs.get('HOST_END')
        self.enddt = datetime.datetime.strptime(self.end, STRP_STRING)
        self.operating_system = attrs.get('operating-system')
        self.fqdn = attrs.get('host-fqdn')
        self.ip = attrs.get('host-ip')
        # host-ip may not be included for host if target is ip address
        if not self.ip:
            try:
                if socket.inet_aton(self.target):
                    self.ip = self.target
                else:
                    raise NessusError('Error parsing host %s, no IP address '
                                      'found' % self.target)
            except:
                raise

        # add timezone
        if self.timezone:
            self.startdt = self.startdt.replace(tzinfo=self.timezone)
            self.enddt = self.enddt.replace(tzinfo=self.timezone)

        # system_type
        for reportitem in self.etree.findall('ReportItem'):
            self.items.append(Item(reportitem))


    @property
    def alive(self):
        """
        True if host is active, False otherwise. It does this
        by checking for the presence of a specific plugin in the report.

        Warning: Nessus must be configured correctly for this to work.
        You must enable "Make the dead hosts appear in the report" under
        "Ping the remote host" in the "Preferences" menu.
        """
        return not any([item.plugin_id == '10180' for item in self.items])

    def todict(self):
        return {'start':self.startdt.isoformat(),
                'end':self.enddt.isoformat(),
                'operating_system':self.operating_system,
                'fqdn':self.fqdn,
                'ip':self.ip,
                'items':[item.todict() for item in self.items]}


class Report(object):
    """Equivalent to the <Report> tag."""
    def __init__(self, xml, timezone=None):
        logger.debug('xml length: %s' % len(xml))

        self.raw_xml = xml
        # garse xml
        etree = ET.fromstring(self.raw_xml)
        # store properties lost after trunctation
        self.policy_name = etree.find('Policy/policyName').text
        # make Report tag root of tree
        self.etree = etree.find('Report')
        self.timezone = timezone
        self.hosts = []
        self._parse()

    def __repr__(self):
        return '<Report: %s>' % self.name

    def _parse(self):
        # store Report level properties
        self.name = self.etree.attrib.get('name')
        for reporthost in self.etree.findall('ReportHost'):
            self.hosts.append(Host(reporthost, self.timezone))

    @property
    def start(self):
        # scan start time calculated from first host start time
        if self.is_empty:
            # raise Exception('Report contained no hosts')
            return None
        dates = [host.startdt for host in self.hosts]
        dates.sort()
        return dates[0]

    @property
    def end(self):
        # scan end time calculated from last host end time
        if self.is_empty:
            # raise Exception('Report contained no hosts')
            raise None
        dates = [host.enddt for host in self.hosts]
        dates.sort()
        return dates[-1]

    def todict(self):
        return {'report':{'hosts':[host.todict() for host in self.hosts]}}

    def tojson(self):
        """Reproduce Nessus Report in JSON output."""
        return json.dumps(self.todict())

    def openports(self):
        """Return a unique list of open ports."""
        raise NotImplemented

    @property
    def is_empty(self):
        return not self.hosts

