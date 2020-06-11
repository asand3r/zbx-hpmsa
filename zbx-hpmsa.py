#!/usr/bin/env python3

import os
import json
import shutil
import urllib3
from hashlib import md5
from socket import gethostbyname
from argparse import ArgumentParser
from xml.etree import ElementTree as eTree
from datetime import datetime, timedelta

import sqlite3
import requests


def install_script(tmp_dir, group):
    """
    Function creates temp dir, init cache db and assign needed right.

    :param tmp_dir: Path to temporary directory
    :type: str
    :param group: Group name to set chown root:group to tmp dir and cache db file
    :type: str
    :return: None
    :rtype: None
    """

    # Create directory for cache and assign rights
    try:
        if not os.path.exists(tmp_dir):
            # Create directory
            os.mkdir(tmp_dir)
            os.chmod(tmp_dir, 0o775)
            print("Cache directory was created at: '{}'".format(tmp_dir))
    except PermissionError:
        raise SystemExit("ERROR: You don't have permissions to create '{}' directory".format(tmp_dir))

    # Init cache db
    if not os.path.exists(CACHE_DB):
        sql_cmd('CREATE TABLE IF NOT EXISTS skey_cache ('
                'dns_name TEXT NOT NULL, '
                'ip TEXT NOT NULL, '
                'proto TEXT NOT NULL, '
                'expired TEXT NOT NULL, '
                'skey TEXT NOT NULL DEFAULT 0, '
                'PRIMARY KEY (dns_name, ip, proto))'
                )
        os.chmod(CACHE_DB, 0o664)
        print("Cache database initialized as: '{}'".format(CACHE_DB))

    # Set owner to tmp dir
    try:
        shutil.chown(tmp_dir, group=group)
        shutil.chown(CACHE_DB, group=group)
        print("Cache directory group set to: '{}'".format(group))
    except LookupError:
        print("WARNING: Cannot find group '{}' to set access rights. Using current user primary group.\n"
              "You must manually check access rights to '{}' for zabbix_server".format(group, CACHE_DB))


def make_cred_hash(cred, isfile=False):
    """
    Return md5 hash of login string.

    :param cred: Login string in 'user_password' format or path to the file with credentials.
    :type cred: str
    :param isfile: Is the 'cred' is path to file.
    :type isfile: bool
    :return: md5 hash.
    :rtype: str
    """

    if isfile:
        try:
            with open(cred, 'r') as login_file:
                login_data = login_file.readline().replace('\n', '').strip()
                if login_data.find('_') != -1:
                    hashed = md5(login_data.encode()).hexdigest()
                else:
                    hashed = login_data
        except FileNotFoundError:
            raise SystemExit("ERROR: File with login data doesn't exists: {}".format(cred))
    else:
        hashed = md5(cred.encode()).hexdigest()
    return hashed


def sql_cmd(query, fetch_all=False):
    """
    Check and execute SQL query.

    :param query: SQL query to execute.
    :type query: str
    :param fetch_all: Set it True to execute fetchall().
    :type fetch_all: bool
    :return: Tuple with SQL query result.
    :rtype: tuple
    """

    try:
        conn = sqlite3.connect(CACHE_DB)
        cursor = conn.cursor()
        try:
            if not fetch_all:
                data = cursor.execute(query).fetchone()
            else:
                data = cursor.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            if str(e).startswith('no such table'):
                raise SystemExit("Cache is empty")
            else:
                raise SystemExit('ERROR: {}. Query: {}'.format(e, query))
        conn.commit()
        conn.close()
        return data
    except sqlite3.OperationalError as e:
        print("CACHE ERROR: (db: {}) {}".format(CACHE_DB, e))


def display_cache():
    """
    Diplay cache data and exit.

    :return: None
    :rtype: None
    """

    print("{:^30} {:^15} {:^7} {:^19} {:^32}".format('hostname', 'ip', 'proto', 'expired', 'sessionkey'))
    print("{:-^30} {:-^15} {:-^7} {:-^19} {:-^32}".format('-', '-', '-', '-', '-'))

    for cache in sql_cmd('SELECT * FROM skey_cache', fetch_all=True):
        name, ip, proto, expired, sessionkey = cache
        print("{:30} {:15} {:^7} {:19} {:32}".format(
            name, ip, proto, datetime.fromtimestamp(float(expired)).strftime("%H:%M:%S %d.%m.%Y"), sessionkey))


def get_skey(msa, hashed_login, use_cache=True):
    """
    Get session key from HP MSA API and and print it.

    :param msa: MSA IP address and DNS name.
    :type msa: tuple
    :param hashed_login: Hashed with md5 login data.
    :type hashed_login: str
    :param use_cache: The function will try to save session key to disk.
    :type use_cache: bool
    :return: Session key or error code.
    :rtype: str
    """

    # Trying to use cached session key
    if use_cache:
        cur_timestamp = datetime.timestamp(datetime.utcnow())
        if not USE_SSL:  # http
            cache_data = sql_cmd('SELECT expired,skey FROM skey_cache WHERE ip="{}" AND proto="http"'.format(msa[0]))
        else:  # https
            cache_data = sql_cmd('SELECT expired,skey '
                                 'FROM skey_cache '
                                 'WHERE dns_name="{}" AND IP ="{}" AND proto="https"'.format(msa[1], msa[0])
                                 )
        if cache_data is not None:
            cache_expired, cached_skey = cache_data
            if cur_timestamp < float(cache_expired):
                return cached_skey
            else:
                return get_skey(msa, hashed_login, use_cache=False)
        else:
            return get_skey(msa, hashed_login, use_cache=False)
    else:
        # Forming URL and trying to make GET query
        msa_conn = msa[1] if VERIFY_SSL else msa[0]
        url = '{}/api/login/{}'.format(msa_conn, hashed_login)
        ret_code, sessionkey, xml = query_xmlapi(url=url, sessionkey=None)

        # 1 - success, write sessionkey to DB and return it
        if ret_code == '1':
            expired = datetime.timestamp(datetime.utcnow() + timedelta(minutes=30))
            if not USE_SSL:
                cache_data = sql_cmd('SELECT ip FROM skey_cache WHERE ip = "{}" AND proto="http"'.format(msa[0]))
                if cache_data is None:
                    sql_cmd('INSERT INTO skey_cache VALUES ('
                            '"{dns}", "{ip}", "http", "{time}", "{skey}")'.format(dns=msa[1], ip=msa[0],
                                                                                  time=expired, skey=sessionkey)
                            )
                else:
                    sql_cmd('UPDATE skey_cache SET skey="{skey}", expired="{expired}" '
                            'WHERE ip="{ip}" AND proto="http"'.format(skey=sessionkey, expired=expired, ip=msa[0])
                            )
            else:
                cache_data = sql_cmd('SELECT dns_name, ip FROM skey_cache '
                                     'WHERE dns_name="{}" AND ip="{}" AND proto="https"'.format(msa[1], msa[0]))
                if cache_data is None:
                    sql_cmd('INSERT INTO skey_cache VALUES ('
                            '"{name}", "{ip}", "https", "{expired}", "{skey}")'.format(name=msa[1], ip=msa[0],
                                                                                       expired=expired,
                                                                                       skey=sessionkey
                                                                                       )
                            )
                else:
                    sql_cmd('UPDATE skey_cache SET skey = "{skey}", expired = "{expired}" '
                            'WHERE dns_name="{name}" AND ip="{ip}" AND proto="https"'.format(skey=sessionkey,
                                                                                             expired=expired,
                                                                                             name=msa[1],
                                                                                             ip=msa[0]
                                                                                             )
                            )
            return sessionkey
        # 2 - Authentication Unsuccessful, return "2"
        elif ret_code == '2':
            return ret_code


def query_xmlapi(url, sessionkey):
    """
    Making HTTP(s) request to HP MSA XML API.

    :param url: URL to make GET request.
    :type url: str
    :param sessionkey: Session key to authorize.
    :type sessionkey: Union[str, None]
    :return: Tuple with return code, return description and etree object <xml.etree.ElementTree.Element>.
    :rtype: tuple
    """

    # Set file where we can find root CA
    ca_file = '/etc/pki/tls/certs/ca-bundle.crt'

    # Makes GET request to URL
    try:
        # Connection timeout in seconds (connection, read).
        timeout = (3, 10)
        full_url = 'https://' + url if USE_SSL else 'http://' + url
        headers = {'sessionKey': sessionkey} if API_VERSION == 2 else {
            'Cookie': "wbiusername={}; wbisessionkey={}".format(MSA_USERNAME, sessionkey)}
        if USE_SSL:
            if VERIFY_SSL:
                response = requests.get(full_url, headers=headers, verify=ca_file, timeout=timeout)
            else:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                response = requests.get(full_url, headers=headers, verify=False, timeout=timeout)
        else:
            response = requests.get(full_url, headers=headers, timeout=timeout)
    except requests.exceptions.SSLError:
        raise SystemExit('ERROR: Cannot verify storage SSL Certificate.')
    except requests.exceptions.ConnectTimeout:
        raise SystemExit('ERROR: Timeout occurred!')
    except requests.exceptions.ConnectionError as e:
        raise SystemExit("ERROR: Cannot connect to storage {}.".format(e))

    # Reading data from server XML response
    try:
        if SAVE_XML is not None and 'login' not in url:
            try:
                with open(SAVE_XML[0], 'w') as xml_file:
                    xml_file.write(response.text)
            except PermissionError:
                raise SystemExit('ERROR: Cannot save XML file to "{}"'.format(args.savexml))
        response_xml = eTree.fromstring(response.content)
        return_code = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='return-code']").text
        return_response = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='response']").text

        return return_code, return_response, response_xml
    except (ValueError, AttributeError) as e:
        raise SystemExit("ERROR: Cannot parse XML. {}".format(e))


def make_lld(msa, component, sessionkey, pretty=False):
    """
    Form LLD JSON for Zabbix server.

    :param msa: MSA DNS name and IP address.
    :type msa: tuple
    :param sessionkey: Session key.
    :type sessionkey: str
    :param pretty: Print output in pretty format
    :type pretty: int
    :param component: Name of storage component.
    :type component: str
    :return: JSON with discovery data.
    :rtype: str
    """

    # Forming URL
    msa_conn = msa[1] if VERIFY_SSL else msa[0]
    url = '{strg}/api/show/{comp}'.format(strg=msa_conn, comp=component)

    # Making request to the API
    resp_return_code, resp_description, xml = query_xmlapi(url, sessionkey)
    if resp_return_code != '0':
        raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))

    # CLI component names to XML API mapping
    comp_names_map = {
        'disks': 'drive', 'vdisks': 'virtual-disk', 'pools': 'pools', 'disk-groups': 'disk-group',
        'volumes': 'volume', 'controllers': 'controllers', 'enclosures': 'enclosures',
        'power-supplies': 'power-supplies', 'fans': 'fan-details', 'ports': 'ports'
    }
    # XML API prop names to Zabbix macro mapping
    comp_props_map = {
        'vdisks': {'{#VDISK.ID}': 'name', '{#VDISK.TYPE}': 'storage-type'},
        'fans': {'{#FAN.ID}': 'durable-id', '{#FAN.LOCATION}': 'location'},
        'ports': {'{#PORT.ID}': 'port', '{#PORT.TYPE}': 'port-type', '{#PORT.SPEED}': 'actual-speed'},
        'pools': {'{#POOL.ID}': 'name', '{#POOL.SN}': 'serial-number', '{#POOL.TYPE}': 'storage-type'},
        'enclosures': {'{#ENCLOSURE.ID}': 'enclosure-id', '{#ENCLOSURE.SN}': 'midplane-serial-number'},
        'volumes': {'{#VOLUME.ID}': 'volume-name', '{#VOLUME.SN}': 'serial-number', '{#VOLUME.TYPE}': 'volume-type'},
        'power-supplies': {'{#POWERSUPPLY.ID}': 'durable-id', '{#POWERSUPPLY.LOCATION}': 'location',
                           '{#POWERSUPPLY.NAME}': 'name'},
        'disks': {'{#DISK.ID}': 'location', '{#DISK.SN}': 'serial-number', '{#DISK.MODEL}': 'model',
                  '{#DISK.ARCH}': 'architecture'},
        'disk-groups': {'{#DG.ID}': 'name', '{#DG.SN}': 'serial-number', '{#DG.TYPE}': 'storage-type',
                        '{#DG.TIER}': 'storage-tier'},
        'controllers': {'{#CONTROLLER.ID}': 'controller-id', '{#CONTROLLER.SN}': 'serial-number',
                        '{#CONTROLLER.IP}': 'ip-address', '{#CONTROLLER.WWN}': 'node-wwn'}
    }

    # Processing response
    all_components = []
    for part in xml.findall("./OBJECT[@name='{}']".format(comp_names_map[component])):
        lld_dict = {}
        for macro, prop in comp_props_map[component].items():
            try:
                xml_prop_value = part.find("./PROPERTY[@name='{}']".format(prop)).text
            except AttributeError:
                xml_prop_value = "UNKNOWN"
            lld_dict[macro] = xml_prop_value
        # Dirty workaround for SFP present status
        if component == 'ports':
            try:
                port_sfp = part.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-present']").text
            except AttributeError:
                port_sfp = "UNKNOWN"
            lld_dict['{#PORT.SFP}'] = port_sfp
        all_components.append(lld_dict)

    # Dumps JSON and return it
    return json.dumps({"data": all_components}, separators=(',', ':'), indent=pretty)


def get_full_json(msa, component, sessionkey, pretty=False, human=False):
    """
    Form text in JSON with storage component data.

    :param msa: MSA DNS name and IP address.
    :type msa: tuple
    :param sessionkey: Session key.
    :type sessionkey: str
    :param pretty: Print in pretty format
    :type pretty: int
    :param component: Name of storage component.
    :type component: str
    :param human: Expand result dict keys in human readable format
    :type: bool
    :return: JSON with all found data.
    :rtype: str
    """

    # Forming URL
    msa_conn = msa[1] if VERIFY_SSL else msa[0]
    url = '{strg}/api/show/{comp}'.format(strg=msa_conn, comp=component)

    # Making request to API
    resp_return_code, resp_description, xml = query_xmlapi(url, sessionkey)
    if resp_return_code != '0':
        raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))

    # Processing XML
    all_components = {}
    if component == 'disks':
        for PROP in xml.findall("./OBJECT[@name='drive']"):
            # Processing main properties
            disk_location = PROP.find("./PROPERTY[@name='location']").text
            disk_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            disk_full_data = {
                "h": disk_health_num
            }

            # Processing advanced properties
            disk_ext = dict()
            disk_ext['t'] = PROP.find("./PROPERTY[@name='temperature-numeric']")
            disk_ext['ts'] = PROP.find("./PROPERTY[@name='temperature-status-numeric']")
            disk_ext['cj'] = PROP.find("./PROPERTY[@name='job-running-numeric']")
            disk_ext['poh'] = PROP.find("./PROPERTY[@name='power-on-hours']")
            for prop, value in disk_ext.items():
                if value is not None:
                    disk_full_data[prop] = value.text
            all_components[disk_location] = disk_full_data
    elif component == 'vdisks':
        for PROP in xml.findall("./OBJECT[@name='virtual-disk']"):
            vdisk_name = PROP.find("./PROPERTY[@name='name']").text
            vdisk_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            vdisk_status_num = PROP.find("./PROPERTY[@name='status-numeric']").text
            vdisk_owner_num = PROP.find("./PROPERTY[@name='owner-numeric']").text
            vdisk_owner_pref_num = PROP.find("./PROPERTY[@name='preferred-owner-numeric']").text
            vdisk_full_data = {
                "h": vdisk_health_num,
                "s": vdisk_status_num,
                "ow": vdisk_owner_num,
                "owp": vdisk_owner_pref_num
            }
            all_components[vdisk_name] = vdisk_full_data
    elif component == 'pools':
        for PROP in xml.findall("./OBJECT[@name='pools']"):
            pool_sn = PROP.find("./PROPERTY[@name='serial-number']").text
            pool_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            pool_owner_num = PROP.find("./PROPERTY[@name='owner-numeric']").text
            pool_owner_pref_num = PROP.find("./PROPERTY[@name='preferred-owner-numeric']").text
            pool_full_data = {
                "h": pool_health_num,
                "ow": pool_owner_num,
                "owp": pool_owner_pref_num
            }
            all_components[pool_sn] = pool_full_data
    elif component == 'disk-groups':
        for PROP in xml.findall("./OBJECT[@name='disk-group']"):
            dg_sn = PROP.find(".PROPERTY[@name='serial-number']").text
            dg_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            dg_status_num = PROP.find("./PROPERTY[@name='status-numeric']").text
            dg_owner_num = PROP.find("./PROPERTY[@name='owner-numeric']").text
            dg_owner_pref_num = PROP.find("./PROPERTY[@name='preferred-owner-numeric']").text
            dg_curr_job_num = PROP.find("./PROPERTY[@name='current-job-numeric']").text
            dg_curr_job_pct = PROP.find("./PROPERTY[@name='current-job-completion']").text
            # current job completion return None if job isn't running, so I'm replacing it with zero if None
            if dg_curr_job_pct is None:
                dg_curr_job_pct = '0'
            dg_full_data = {
                "h": dg_health_num,
                "s": dg_status_num,
                "ow": dg_owner_num,
                "owp": dg_owner_pref_num,
                "cj": dg_curr_job_num,
                "cjp": dg_curr_job_pct.rstrip('%')
            }
            all_components[dg_sn] = dg_full_data
    elif component == 'volumes':
        for PROP in xml.findall("./OBJECT[@name='volume']"):
            vol_sn = PROP.find("./PROPERTY[@name='serial-number']").text
            vol_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            vol_owner_num = PROP.find("./PROPERTY[@name='owner-numeric']").text
            vol_owner_pref_num = PROP.find("./PROPERTY[@name='preferred-owner-numeric']").text
            vol_full_data = {
                "h": vol_health_num,
                "ow": vol_owner_num,
                "owp": vol_owner_pref_num
            }
            all_components[vol_sn] = vol_full_data
    elif component == 'controllers':
        for PROP in xml.findall("./OBJECT[@name='controllers']"):
            # Processing main controller properties
            ctrl_id = PROP.find("./PROPERTY[@name='controller-id']").text
            ctrl_sc_fw = PROP.find("./PROPERTY[@name='sc-fw']").text
            ctrl_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            ctrl_status_num = PROP.find("./PROPERTY[@name='status-numeric']").text
            ctrl_rd_status_num = PROP.find("./PROPERTY[@name='redundancy-status-numeric']").text

            # Get controller statistics
            url = '{strg}/api/show/{comp}/{ctrl}'.format(strg=msa_conn, comp='controller-statistics', ctrl=ctrl_id)

            # Making request to API
            stats_ret_code, stats_descr, stats_xml = query_xmlapi(url, sessionkey)
            if stats_ret_code != '0':
                raise SystemExit('ERROR: {} : {}'.format(stats_ret_code, stats_descr))

            # TODO: I don't know, is it good solution, but it's one more query to XML API
            ctrl_cpu_load = stats_xml.find("./OBJECT[@name='controller-statistics']/PROPERTY[@name='cpu-load']").text
            ctrl_iops = stats_xml.find("./OBJECT[@name='controller-statistics']/PROPERTY[@name='iops']").text

            # Making full controller dict
            ctrl_full_data = {
                "h": ctrl_health_num,
                "s": ctrl_status_num,
                "rs": ctrl_rd_status_num,
                "cpu": ctrl_cpu_load,
                "io": ctrl_iops,
                "fw": ctrl_sc_fw
            }

            # Processing advanced controller properties
            ctrl_ext = dict()
            ctrl_ext['fh'] = PROP.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='health-numeric']")
            ctrl_ext['fs'] = PROP.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='status-numeric']")
            for prop, value in ctrl_ext.items():
                if value is not None:
                    ctrl_full_data[prop] = value.text
            all_components[ctrl_id] = ctrl_full_data
    elif component == 'enclosures':
        for PROP in xml.findall("./OBJECT[@name='enclosures']"):
            # Processing main enclosure properties
            encl_id = PROP.find("./PROPERTY[@name='enclosure-id']").text
            encl_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            encl_status_num = PROP.find("./PROPERTY[@name='status-numeric']").text
            # Making full enclosure dict
            encl_full_data = {
                "h": encl_health_num,
                "s": encl_status_num
            }
            all_components[encl_id] = encl_full_data
    elif component == 'power-supplies':
        # Getting info about all power supplies
        for PS in xml.findall("./OBJECT[@name='power-supplies']"):
            # Processing main power supplies properties
            ps_id = PS.find("./PROPERTY[@name='durable-id']").text
            ps_name = PS.find("./PROPERTY[@name='name']").text
            # Exclude voltage regulators
            if ps_name.lower().find('voltage regulator') == -1:
                ps_health_num = PS.find("./PROPERTY[@name='health-numeric']").text
                ps_status_num = PS.find("./PROPERTY[@name='status-numeric']").text
                ps_dc12v = PS.find("./PROPERTY[@name='dc12v']").text
                ps_dc5v = PS.find("./PROPERTY[@name='dc5v']").text
                ps_dc33v = PS.find("./PROPERTY[@name='dc33v']").text
                ps_dc12i = PS.find("./PROPERTY[@name='dc12i']").text
                ps_dc5i = PS.find("./PROPERTY[@name='dc5i']").text
                ps_full_data = {
                    "h": ps_health_num,
                    "s": ps_status_num,
                    "12v": ps_dc12v,
                    "5v": ps_dc5v,
                    "33v": ps_dc33v,
                    "12i": ps_dc12i,
                    "5i": ps_dc5i
                }
                # Processing advanced power supplies properties
                ps_ext = dict()
                ps_ext['t'] = PS.find("./PROPERTY[@name='dctemp']")
                for prop, value in ps_ext.items():
                    if value is not None:
                        ps_full_data[prop] = value.text
                all_components[ps_id] = ps_full_data
    elif component == 'fans':
        # Getting info about all fans
        for FAN in xml.findall("./OBJECT[@name='fan-details']"):
            # Processing main fan properties
            fan_id = FAN.find(".PROPERTY[@name='durable-id']").text
            fan_health_num = FAN.find(".PROPERTY[@name='health-numeric']").text
            fan_status_num = FAN.find(".PROPERTY[@name='status-numeric']").text
            fan_speed = FAN.find(".PROPERTY[@name='speed']").text
            fan_full_data = {
                "h": fan_health_num,
                "s": fan_status_num,
                "sp": fan_speed
            }
            all_components[fan_id] = fan_full_data
    elif component == 'ports':
        for FC in xml.findall("./OBJECT[@name='ports']"):
            # Processing main ports properties
            port_name = FC.find("./PROPERTY[@name='port']").text
            port_health_num = FC.find("./PROPERTY[@name='health-numeric']").text
            port_full_data = {
                "h": port_health_num
            }

            # Processing advanced ports properties
            port_ext = dict()
            port_ext['ps'] = FC.find("./PROPERTY[@name='status-numeric']")
            for prop, value in port_ext.items():
                if value is not None:
                    port_full_data[prop] = value.text

            # SFP Status
            # Because of before 1050/2050 API has no numeric property for sfp-status, creating mapping self
            sfp_status_map = {"Not compatible": '0', "Incorrect protocol": '1', "Not present": '2', "OK": '3'}
            sfp_status_char = FC.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-status']")
            sfp_status_num = FC.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-status-numeric']")
            if sfp_status_num is not None:
                port_full_data['ss'] = sfp_status_num.text
            else:
                if sfp_status_char is not None:
                    port_full_data['ss'] = sfp_status_map[sfp_status_char.text]

            all_components[port_name] = port_full_data
    # Transform dict keys to human readable format if '--human' argument is given
    if human:
        all_components = expand_dict(all_components)
    return json.dumps(all_components, separators=(',', ':'), indent=pretty)


def expand_dict(init_dict):
    """
    Expand dict keys to full names

    :param init_dict: Initial dict
    :type: dict
    :return: Dictionary with fully expanded key names
    :rtype: dict
    """

    # Match dict for print output in human readable format
    m = {'h': 'health', 's': 'status', 'ow': 'owner', 'owp': 'owner-preferred', 't': 'temperature',
         'ts': 'temperature-status', 'cj': 'current-job', 'poh': 'power-on-hours', 'rs': 'redundancy-status',
         'fw': 'firmware-version', 'sp': 'speed', 'ps': 'port-status', 'ss': 'sfp-status',
         'fh': 'flash-health', 'fs': 'flash-status', '12v': 'power-12v', '5v': 'power-5v',
         '33v': 'power-33v', '12i': 'power-12i', '5i': 'power-5i', 'io': 'iops', 'cpu': 'cpu-load',
         'cjp': 'current-job-completion'
         }

    result_dict = {}
    for compid, metrics in init_dict.items():
        h_metrics = {}
        for key in metrics.keys():
            h_metrics[m[key]] = metrics[key]
        result_dict[compid] = h_metrics
    return result_dict


if __name__ == '__main__':
    # Current program version
    VERSION = '0.7.4'
    MSA_PARTS = ('disks', 'vdisks', 'controllers', 'enclosures', 'fans',
                 'power-supplies', 'ports', 'pools', 'disk-groups', 'volumes')

    # Main parser
    main_parser = ArgumentParser(description='Zabbix script for HP MSA devices.', add_help=True)
    main_parser.add_argument('-a', '--api', type=int, default=2, choices=(1, 2), help='MSA API version (default: 2)')
    main_parser.add_argument('-u', '--username', default='monitor', type=str, help='Username to connect with')
    main_parser.add_argument('-p', '--password', default='!monitor', type=str, help='Password for the username')
    main_parser.add_argument('-f', '--login-file', nargs=1, type=str, help='Path to the file with credentials')
    main_parser.add_argument('-v', '--version', action='version', version=VERSION, help='Print script version and exit')
    main_parser.add_argument('-s', '--save-xml', type=str, nargs=1, help='Save response to XML file')
    main_parser.add_argument('-t', '--tmp-dir', type=str, nargs=1, default='/var/tmp/zbx-hpmsa/', help='Temp directory')
    main_parser.add_argument('--ssl', type=str, choices=('direct', 'verify'), help='Use secure connections')
    main_parser.add_argument('--pretty', action='store_true', help='Print output in pretty format')
    main_parser.add_argument('--human', action='store_true', help='Expose shorten response fields')

    # Subparsers
    subparsers = main_parser.add_subparsers(help='Possible options list', dest='command')

    # Install script command
    install_parser = subparsers.add_parser('install', help='Do preparation tasks')
    install_parser.add_argument('--reinstall', action='store_true', help='Recreate script temp dir and cache DB')
    install_parser.add_argument('--group', type=str, default='zabbix', help='Temp directory owner group')

    # Show script cache
    cache_parser = subparsers.add_parser('cache', help='Operations with cache')
    cache_parser.add_argument('--show', action='store_true', help='Display cache data')
    cache_parser.add_argument('--drop', action='store_true', help='Drop cache data')

    # LLD script command
    lld_parser = subparsers.add_parser('lld', help='Retrieve LLD data from MSA')
    lld_parser.add_argument('msa', type=str, help='MSA address (DNS name or IP)')
    lld_parser.add_argument('part', type=str, help='MSA part name', choices=MSA_PARTS)

    # FULL script command
    full_parser = subparsers.add_parser('full', help='Retrieve metrics data for a MSA component')
    full_parser.add_argument('msa', type=str, help='MSA connection address (DNS name or IP)')
    full_parser.add_argument('part', type=str, help='MSA part name', choices=MSA_PARTS)

    args = main_parser.parse_args()

    API_VERSION = args.api
    TMP_DIR = args.tmp_dir
    CACHE_DB = TMP_DIR.rstrip('/') + '/zbx-hpmsa.cache.db'

    if args.command in ('lld', 'full'):
        # Set some global variables
        SAVE_XML = args.save_xml
        USE_SSL = args.ssl in ('direct', 'verify')
        VERIFY_SSL = args.ssl == 'verify'
        MSA_USERNAME = args.username
        MSA_PASSWORD = args.password
        to_pretty = 2 if args.pretty else None

        # (IP, DNS)
        IS_IP = all(elem.isdigit() for elem in args.msa.split('.'))
        MSA_CONNECT = args.msa if IS_IP else gethostbyname(args.msa), args.msa

        # Make login hash string
        if args.login_file is not None:
            CRED_HASH = make_cred_hash(args.login_file, isfile=True)
        else:
            CRED_HASH = make_cred_hash('_'.join([MSA_USERNAME, MSA_PASSWORD]))

        # Getting sessionkey
        skey = get_skey(MSA_CONNECT, CRED_HASH)

        # Make discovery
        if args.command == 'lld':
            print(make_lld(MSA_CONNECT, args.part, skey, to_pretty))
        # Getting full components data in JSON
        elif args.command == 'full':
            print(get_full_json(MSA_CONNECT, args.part, skey, to_pretty, args.human))
    # Preparations tasks
    elif args.command == 'install':
        TMP_GROUP = args.group
        if args.reinstall:
            print("Removing '{}' and '{}'".format(CACHE_DB, TMP_DIR))
            os.remove(CACHE_DB)
            os.rmdir(TMP_DIR)
            install_script(TMP_DIR, TMP_GROUP)
        else:
            install_script(TMP_DIR, TMP_GROUP)
    # Operations with cache
    elif args.command == 'cache':
        if args.show:
            display_cache()
        elif args.drop:
            sql_cmd('DELETE FROM skey_cache;')
        # Default is --show
        else:
            display_cache()
        exit(0)
