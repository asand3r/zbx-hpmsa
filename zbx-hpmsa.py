#!/usr/bin/env python3

import os
import json
import shutil

import urllib3
from hashlib import md5
from typing import Union
from socket import gethostbyname
from argparse import ArgumentParser
from xml.etree import ElementTree as eTree
from datetime import datetime, timedelta

import sqlite3
import requests


def install_script(tmp_dir: str, group: str) -> None:
    """Creates temp dir, init cache db and assign needed right

    :param tmp_dir: Path to temporary directory
    :param group: Group name to set chown root:group to tmp dir and cache db file
    """

    try:
        if not os.path.exists(tmp_dir):
            os.mkdir(tmp_dir)
            os.chmod(tmp_dir, 0o775)
            print(f'Cache directory has been created: "{tmp_dir}"')
    except PermissionError:
        raise SystemExit(f'ERROR: You have no permissions to create f"{tmp_dir}" directory')

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
        print(f'Cache database initialized: "{CACHE_DB}"')

    try:
        shutil.chown(tmp_dir, group=group)
        shutil.chown(CACHE_DB, group=group)
        print(f'Cache directory group owner set to: "{group}")')
    except LookupError:
        print(f'Cannot find group "{group} to set access rights. Using current user primary group')


def make_cred_hash(cred: str, isfile: bool = False) -> str:
    """Return md5 hash of login string

    :param cred: Login string in 'user_password' format or path to the file with credentials
    :param isfile: Is the 'cred' is path to file
    :return: md5 hash
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
            raise SystemExit(f'Cannot find file "{cred}" with login data')
    else:
        hashed = md5(cred.encode()).hexdigest()
    return hashed


def sql_cmd(query: str, fetch_all: bool = False) -> tuple:
    """Check and execute SQL query

    :param query: SQL query to execute
    :param fetch_all: Set it True to execute fetchall()
    :return: Tuple with SQL query result
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
            raise SystemExit(f'ERROR: {e}. Query: {query}')
        conn.commit()
        conn.close()
        return data
    except sqlite3.OperationalError as e:
        print(f'ERROR: "{e}"')


def display_cache() -> None:
    """Display cache data and exit"""

    print("{:^30} {:^15} {:^7} {:^19} {:^32}".format('hostname', 'ip', 'proto', 'expired', 'sessionkey'))
    print("{:-^30} {:-^15} {:-^7} {:-^19} {:-^32}".format('-', '-', '-', '-', '-'))

    for cache in sql_cmd('SELECT * FROM skey_cache', fetch_all=True):
        name, ip, proto, expired, sessionkey = cache
        print("{:30} {:15} {:^7} {:19} {:32}".format(
            name, ip, proto, datetime.fromtimestamp(float(expired)).strftime("%H:%M:%S %d.%m.%Y"), sessionkey))


def get_skey(msa: tuple, hashed_login: str, use_cache: bool = True) -> str:
    """Get session key from HP MSA API and and print it

    :param msa: MSA IP address and DNS name
    :param hashed_login: Hashed with md5 login data
    :param use_cache: The function will try to save session key to disk
    :return: Session key
    """

    if use_cache:
        cur_timestamp = datetime.timestamp(datetime.utcnow())
        if not USE_SSL:
            cache_data = sql_cmd(f'SELECT expired, skey FROM skey_cache WHERE ip="{msa[0]}" AND proto="http"')
        else:
            cache_data = sql_cmd(
                f'SELECT expired,skey FROM skey_cache WHERE dns_name="{msa[1]}" AND IP ="{msa[0]}" AND proto="https"')
        if cache_data:
            cache_expired, cached_skey = cache_data
            if cur_timestamp < float(cache_expired):
                return cached_skey
        return get_skey(msa, hashed_login, use_cache=False)
    else:
        msa_conn = msa[1] if VERIFY_SSL else msa[0]
        ret_code, sessionkey, xml = query_xmlapi(url=f'{msa_conn}/api/login/{hashed_login}', sessionkey=None)
        if ret_code != '1':
            raise SystemExit(f'ERROR: MSA Authentication unsuccessful')

        expired = datetime.timestamp(datetime.utcnow() + timedelta(minutes=30))
        if not USE_SSL:
            cache_data = sql_cmd(f'SELECT ip FROM skey_cache WHERE ip = "{msa[0]}" AND proto="http"')
            if cache_data:
                sql_cmd(f'INSERT INTO skey_cache VALUES ("{msa[1]}", "{msa[0]}", "http", "{expired}", "{sessionkey}")')
            else:
                sql_cmd(f'UPDATE skey_cache SET skey="{sessionkey}", expired="{expired}"'
                        f'WHERE ip="{msa[0]}" AND proto="http"')
        else:
            cache_data = sql_cmd(
                f'SELECT dns_name, ip FROM skey_cache WHERE dns_name="{msa[1]}" AND ip="{msa[0]}" AND proto="https"')
            if cache_data:
                sql_cmd(
                    f'INSERT INTO skey_cache VALUES ("{msa[1]}", "{[msa[0]]}", "https", "{expired}", "{sessionkey}")')
            else:
                sql_cmd(f'UPDATE skey_cache SET skey = "{sessionkey}", expired = "{expired}"'
                        f'WHERE dns_name="{msa[1]}" AND ip="{msa[0]}" AND proto="https"')
        return sessionkey


def query_xmlapi(url: str, sessionkey: Union[str, None]) -> tuple:
    """Making HTTP(s) request to HP MSA XML API.

    :param url: URL to make GET request
    :param sessionkey: Session key to authorize
    :return: Tuple with return code, return description and etree object <xml.etree.ElementTree.Element>
    """

    ca_file = '/etc/pki/tls/certs/ca-bundle.crt'
    try:
        # Timeouts - connection timeout, read timeout
        timeout = (3, 10)
        full_url = 'https://' + url if USE_SSL else 'http://' + url
        if API_VERSION == 2:
            headers = {'sessionKey': sessionkey}
        else:
            headers = {'Cookie': f'wbiusername={MSA_USERNAME}; wbisessionkey={sessionkey}'}
        if not USE_SSL:
            response = requests.get(full_url, headers=headers, timeout=timeout)
        else:
            if VERIFY_SSL:
                response = requests.get(full_url, headers=headers, verify=ca_file, timeout=timeout)
            else:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                response = requests.get(full_url, headers=headers, verify=False, timeout=timeout)
    except requests.exceptions.SSLError:
        raise SystemExit('ERROR: Cannot verify storage SSL Certificate')
    except requests.exceptions.ConnectTimeout:
        raise SystemExit('ERROR: Timeout occurred')
    except requests.exceptions.ConnectionError as e:
        raise SystemExit(f'ERROR: Cannot connect to storage: "{e}"')

    try:
        if SAVE_XML is not None and 'login' not in url:
            try:
                with open(SAVE_XML[0], 'w') as xml_file:
                    xml_file.write(response.text)
            except PermissionError:
                raise SystemExit(f'Cannot save XML file to "{args.savexml}"')
        response_xml = eTree.fromstring(response.content)
        return_code = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='return-code']").text
        return_response = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='response']").text
        return return_code, return_response, response_xml
    except (ValueError, AttributeError) as e:
        raise SystemExit(f'Cannot parse XML: "{e}"')


def make_lld(msa: tuple, component: str, sessionkey: str, pretty: int = 0) -> str:
    """Form LLD JSON for Zabbix server.

    :param msa: MSA DNS name and IP address
    :param sessionkey: Session key.
    :param pretty: Print output in pretty format
    :param component: Name of storage component
    :return: JSON with discovery data
    """

    msa_conn = msa[1] if VERIFY_SSL else msa[0]
    url = f'{msa_conn}/api/show/{component}'
    resp_rcode, resp_descr, xml = query_xmlapi(url, sessionkey)
    if resp_rcode != '0':
        raise SystemExit(f'ERROR: [{resp_rcode}] {resp_descr}')

    lld = []
    if component == 'disks':
        for disk in xml.findall("./OBJECT[@name='drive']"):
            d_id = disk.find("./PROPERTY[@name='location']").text
            d_sn = disk.find("./PROPERTY[@name='serial-number']").text
            d_model = disk.find("./PROPERTY[@name='model']").text
            d_arch = disk.find("./PROPERTY[@name='architecture']").text
            lld.append({"{#DISK.ID}": d_id, "{#DISK.SN}": d_sn, "{#DISK.MODEL}": d_model, "{#DISK.ARCH}": d_arch})
    # vdisks is deprecated HPE MSA since 1040/2040
    elif component == 'vdisks':
        for vdisk in xml.findall("./OBJECT[@name='virtual-disk']"):
            vd_id = vdisk.find("./PROPERTY[@name='name']").text
            try:
                vd_type = vdisk.find("./PROPERTY[@name='storage-type']").text
            except AttributeError:
                vd_type = "UNKNOWN"
            lld.append({"{#VDISK.ID}": vd_id, "{#VDISK.TYPE}": vd_type})
    elif component == 'pools':
        for pool in xml.findall("./OBJECT[@name='pools']"):
            p_id = pool.find("./PROPERTY[@name='name']").text
            p_type = pool.find("./PROPERTY[@name='storage-type']").text
            p_sn = pool.find("./PROPERTY[@name='serial-number']").text
            lld.append({"{#POOL.ID}": p_id, "{#POOL.SN}": p_sn, "{#POOL.TYPE}": p_type})
    elif component == 'disk-groups':
        for dg in xml.findall("./OBJECT[@name='disk-group']"):
            dg_id = dg.find("./PROPERTY[@name='name']").text
            dg_type = dg.find("./PROPERTY[@name='storage-type']").text
            dg_sn = dg.find(".PROPERTY[@name='serial-number']").text
            dg_tier = dg.find("./PROPERTY[@name='storage-tier']").text
            lld.append({"{#DG.ID}": dg_id, "{#DG.SN}": dg_sn, "{#DG.TYPE}": dg_type, "{#DG.TIER}": dg_tier})
    elif component == 'volumes':
        for vol in xml.findall("./OBJECT[@name='volume']"):
            v_id = vol.find("./PROPERTY[@name='volume-name']").text
            v_type = vol.find("./PROPERTY[@name='volume-type']").text
            v_sn = vol.find("./PROPERTY[@name='serial-number']").text
            lld.append({"{#VOLUME.ID}": v_id, "{#VOLUME.SN}": v_sn, "{#VOLUME.TYPE}": v_type})
    elif component == 'controllers':
        for ctrl in xml.findall("./OBJECT[@name='controllers']"):
            c_id = ctrl.find("./PROPERTY[@name='controller-id']").text
            c_sn = ctrl.find("./PROPERTY[@name='serial-number']").text
            c_ip = ctrl.find("./PROPERTY[@name='ip-address']").text
            c_wwn = ctrl.find("./PROPERTY[@name='node-wwn']").text
            lld.append({"{#CTRL.ID}": c_id, "{#CTRL.SN}": c_sn, "{#CTRL.IP}": c_ip, "{#CTRL.WWN}": c_wwn})
    elif component == 'enclosures':
        for encl in xml.findall("./OBJECT[@name='enclosures']"):
            e_id = encl.find("./PROPERTY[@name='enclosure-id']").text
            e_sn = encl.find("./PROPERTY[@name='midplane-serial-number']").text
            lld.append({"{#ENCL.ID}": e_id, "{#ENCL.SN}": e_sn})
    elif component == 'power-supplies':
        for PS in xml.findall("./OBJECT[@name='power-supplies']"):
            p_id = PS.find("./PROPERTY[@name='durable-id']").text
            p_loc = PS.find("./PROPERTY[@name='location']").text
            p_name = PS.find("./PROPERTY[@name='name']").text
            # Exclude voltage regulators from discovery
            if p_name.lower().find('voltage regulator') == -1:
                lld.append({"{#POWERSUPPLY.ID}": p_id, "{#POWERSUPPLY.LOCATION}": p_loc})
    elif component == 'fans':
        for fan in xml.findall("./OBJECT[@name='fan-details']"):
            f_id = fan.find("./PROPERTY[@name='durable-id']").text
            f_loc = fan.find("./PROPERTY[@name='location']").text
            lld.append({"{#FAN.ID}": f_id, "{#FAN.LOCATION}": f_loc})
    elif component == 'ports':
        for port in xml.findall("./OBJECT[@name='ports']"):
            p_id = port.find("./PROPERTY[@name='port']").text
            p_type = port.find("./PROPERTY[@name='port-type']").text
            p_speed = port.find("./PROPERTY[@name='actual-speed']").text
            p_sfp = port.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-present']").text
            lld.append({"{#PORT.ID}": p_id, "{#PORT.TYPE}": p_type, "{#PORT.SPEED}": p_speed, "{#PORT.SFP}": p_sfp})
    return json.dumps({"data": lld}, separators=(',', ':'), indent=pretty)


def get_full(msa: tuple, component: str, sessionkey: str, pretty: int = 0, human: bool = False) -> str:
    """Form text in JSON with storage component data

    :param msa: MSA DNS name and IP address
    :param sessionkey: Session key
    :param pretty: Print in pretty format
    :param component: Name of storage component
    :param human: Expand result dict keys in human readable format
    :return: JSON with all found data
    """

    msa_conn = msa[1] if VERIFY_SSL else msa[0]
    url = f'{msa_conn}/api/show/{component}'

    resp_rcode, resp_descr, xml = query_xmlapi(url, sessionkey)
    if resp_rcode != '0':
        raise SystemExit(f'ERROR: [{resp_rcode}]: {resp_descr}')

    full = {}
    if component == 'disks':
        for disk in xml.findall("./OBJECT[@name='drive']"):
            d_loc = disk.find("./PROPERTY[@name='location']").text
            d_health = disk.find("./PROPERTY[@name='health-numeric']").text
            d_full = {"h": d_health}

            d_ext = dict()
            d_ext['t'] = disk.find("./PROPERTY[@name='temperature-numeric']")
            d_ext['ts'] = disk.find("./PROPERTY[@name='temperature-status-numeric']")
            d_ext['cj'] = disk.find("./PROPERTY[@name='job-running-numeric']")
            d_ext['poh'] = disk.find("./PROPERTY[@name='power-on-hours']")
            for prop, value in d_ext.items():
                if value:
                    d_full[prop] = value.text
            full[d_loc] = d_full
    elif component == 'vdisks':
        for vdisk in xml.findall("./OBJECT[@name='virtual-disk']"):
            vd_name = vdisk.find("./PROPERTY[@name='name']").text
            vd_health = vdisk.find("./PROPERTY[@name='health-numeric']").text
            vd_status = vdisk.find("./PROPERTY[@name='status-numeric']").text
            vd_owner = vdisk.find("./PROPERTY[@name='owner-numeric']").text
            vd_owner_pref = vdisk.find("./PROPERTY[@name='preferred-owner-numeric']").text
            full[vd_name] = {"h": vd_health, "s": vd_status, "ow": vd_owner, "owp": vd_owner_pref}
    elif component == 'pools':
        for pool in xml.findall("./OBJECT[@name='pools']"):
            p_sn = pool.find("./PROPERTY[@name='serial-number']").text
            p_health = pool.find("./PROPERTY[@name='health-numeric']").text
            p_owner = pool.find("./PROPERTY[@name='owner-numeric']").text
            p_owner_pref = pool.find("./PROPERTY[@name='preferred-owner-numeric']").text
            full[p_sn] = {"h": p_health, "ow": p_owner, "owp": p_owner_pref}
    elif component == 'disk-groups':
        for dg in xml.findall("./OBJECT[@name='disk-group']"):
            dg_sn = dg.find(".PROPERTY[@name='serial-number']").text
            dg_health = dg.find("./PROPERTY[@name='health-numeric']").text
            dg_status = dg.find("./PROPERTY[@name='status-numeric']").text
            dg_owner = dg.find("./PROPERTY[@name='owner-numeric']").text
            dg_owner_pref = dg.find("./PROPERTY[@name='preferred-owner-numeric']").text
            dg_cjob = dg.find("./PROPERTY[@name='current-job-numeric']").text
            dg_cjob_pct = dg.find("./PROPERTY[@name='current-job-completion']").text
            # current job completion return None if job isn't running, replacing it with zero if None
            dg_cjob_pct = '0' if dg_cjob_pct is None else dg_cjob_pct.rstrip('%')
            full[dg_sn] = {
                "h": dg_health, "s": dg_status, "ow": dg_owner, "owp": dg_owner_pref, "cj": dg_cjob, "cjp": dg_cjob_pct}
    elif component == 'volumes':
        for volume in xml.findall("./OBJECT[@name='volume']"):
            v_sn = volume.find("./PROPERTY[@name='serial-number']").text
            v_health = volume.find("./PROPERTY[@name='health-numeric']").text
            v_owner = volume.find("./PROPERTY[@name='owner-numeric']").text
            v_owner_pref = volume.find("./PROPERTY[@name='preferred-owner-numeric']").text
            full[v_sn] = {"h": v_health, "ow": v_owner, "owp": v_owner_pref}
    elif component == 'controllers':
        for PROP in xml.findall("./OBJECT[@name='controllers']"):
            c_id = PROP.find("./PROPERTY[@name='controller-id']").text
            c_sc_fw = PROP.find("./PROPERTY[@name='sc-fw']").text
            c_health = PROP.find("./PROPERTY[@name='health-numeric']").text
            c_status = PROP.find("./PROPERTY[@name='status-numeric']").text
            c_rstatus = PROP.find("./PROPERTY[@name='redundancy-status-numeric']").text

            # Controller statistics
            url = f'{msa_conn}/api/show/controller-statistics/{c_id}'
            resp_code, resp_descr, c_xml = query_xmlapi(url, sessionkey)
            if resp_code != '0':
                raise SystemExit(f'ERROR: [{resp_code}]: {resp_descr}')
            c_cpu_load = c_xml.find("./OBJECT[@name='controller-statistics']/PROPERTY[@name='cpu-load']").text
            c_iops = c_xml.find("./OBJECT[@name='controller-statistics']/PROPERTY[@name='iops']").text

            c_full = {"h": c_health, "s": c_status, "rs": c_rstatus, "cpu": c_cpu_load, "io": c_iops, "fw": c_sc_fw}

            # Processing advanced controller properties
            c_fh = PROP.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='health-numeric']")
            c_fs = PROP.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='status-numeric']")
            if c_fh:
                c_full['fh'] = c_fh.text
            if c_fs:
                c_full['fs'] = c_fh.text
            full[c_id] = c_full
    elif component == 'enclosures':
        for encl in xml.findall("./OBJECT[@name='enclosures']"):
            e_id = encl.find("./PROPERTY[@name='enclosure-id']").text
            e_health = encl.find("./PROPERTY[@name='health-numeric']").text
            e_status = encl.find("./PROPERTY[@name='status-numeric']").text
            full[e_id] = {"h": e_health, "s": e_status}
    elif component == 'power-supplies':
        for ps in xml.findall("./OBJECT[@name='power-supplies']"):
            ps_id = ps.find("./PROPERTY[@name='durable-id']").text
            ps_name = ps.find("./PROPERTY[@name='name']").text
            # Exclude voltage regulators
            if ps_name.lower().find('voltage regulator') != -1:
                continue
            ps_health = ps.find("./PROPERTY[@name='health-numeric']").text
            ps_status = ps.find("./PROPERTY[@name='status-numeric']").text
            ps_dc12v = ps.find("./PROPERTY[@name='dc12v']").text
            ps_dc5v = ps.find("./PROPERTY[@name='dc5v']").text
            ps_dc33v = ps.find("./PROPERTY[@name='dc33v']").text
            ps_dc12i = ps.find("./PROPERTY[@name='dc12i']").text
            ps_dc5i = ps.find("./PROPERTY[@name='dc5i']").text
            ps_full = {"h": ps_health, "s": ps_status, "12v": ps_dc12v,
                       "5v": ps_dc5v, "33v": ps_dc33v, "12i": ps_dc12i, "5i": ps_dc5i}
            ps_temp = ps.find("./PROPERTY[@name='dctemp']")
            if ps_temp:
                ps_full['t'] = ps_temp.text
            full[ps_id] = ps_full
    elif component == 'fans':
        for fan in xml.findall("./OBJECT[@name='fan-details']"):
            f_id = fan.find(".PROPERTY[@name='durable-id']").text
            f_health = fan.find(".PROPERTY[@name='health-numeric']").text
            f_status = fan.find(".PROPERTY[@name='status-numeric']").text
            f_speed = fan.find(".PROPERTY[@name='speed']").text
            full[f_id] = {"h": f_health, "s": f_status, "sp": f_speed}
    elif component == 'ports':
        for port in xml.findall("./OBJECT[@name='ports']"):
            p_name = port.find("./PROPERTY[@name='port']").text
            p_health = port.find("./PROPERTY[@name='health-numeric']").text
            port_full = {"h": p_health}
            p_ps = port.find("./PROPERTY[@name='status-numeric']")
            if p_ps:
                port_full['ps'] = p_ps.text

            # Before 1050/2050 API has no numeric property for sfp-status
            sfp_status_map = {"Not compatible": '0', "Incorrect protocol": '1', "Not present": '2', "OK": '3'}
            sfp_status = port.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-status']")
            sfp_status_num = port.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-status-numeric']")
            if sfp_status_num:
                port_full['ss'] = sfp_status_num.text
            else:
                if sfp_status:
                    port_full['ss'] = sfp_status_map[sfp_status.text]
            full[p_name] = port_full
    if human:
        full = expand_dict(full)
    return json.dumps(full, separators=(',', ':'), indent=pretty)


def get_super(msa: tuple, sessionkey: str, pretty: int = 0) -> str:
    """Query /show/configuration for super-discovery

    :param msa: MSA DNS name and IP address
    :param sessionkey: Session key
    :param pretty: Print in pretty format
    :return: JSON with all found data
    """

    def get_common_attr(xml_obj: eTree, attrs: dict) -> dict:
        """Extract common component attributes from XML"""

        result = {}
        for key, attr in attrs.items():
            val = xml_obj.find(f"./PROPERTY[@name='{attr}']").text
            if val is None or val.isspace():
                val = 'N/A'
            if val.isdigit():
                val = int(val)
            result[key] = val
        return result

    msa_conn = msa[1] if VERIFY_SSL else msa[0]
    url = f'{msa_conn}/api/show/configuration'

    resp_code, resp_descr, xml = query_xmlapi(url, sessionkey)
    if resp_code != '0':
        raise SystemExit(f'ERROR: {resp_code} : {resp_descr}')

    sdata = {}
    for part in ['sys', 'encl', 'ctrl', 'ports', 'ps', 'fans', 'drives', 'pools', 'dg', 'vd']:
        sdata[part] = []

    for prop in xml.findall("./OBJECT[@name='system-information']"):
        sys_attrs = {'n': 'system-name', 'c': 'system-contact', 'l': 'system-location', 'm': 'system-information',
                     'sn': 'midplane-serial-number'}
        sdata['sys'].append(get_common_attr(prop, sys_attrs))

    for en in xml.findall("./OBJECT[@name='enclosures']"):
        en_attrs = {'i': 'enclosure-id', 'sn': 'midplane-serial-number', 's': 'status-numeric', 'h': 'health-numeric'}
        sdata['encl'].append(get_common_attr(en, en_attrs))

        for ctrl in en.findall("./OBJECT[@name='controllers']"):
            c_attrs = {'i': 'controller-id', 'sn': 'serial-number', 'p': 'position-numeric', 'ip': 'ip-address',
                       'fw': 'sc-fw', 's': 'status-numeric', 'h': 'health-numeric', 'rs': 'redundancy-status-numeric'}
            c_data = get_common_attr(ctrl, c_attrs)
            c_data['mac'] = ctrl.find(".//PROPERTY[@name='mac-address']").text
            c_data['cfs'] = int(ctrl.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='status-numeric']").text)
            c_data['cfh'] = int(ctrl.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='health-numeric']").text)
            c_data['sps'] = int(ctrl.find("./OBJECT[@name='expander-port']/PROPERTY[@name='status-numeric']").text)
            c_data['sph'] = int(ctrl.find("./OBJECT[@name='expander-port']/PROPERTY[@name='health-numeric']").text)
            sdata['ctrl'].append(c_data)

            # Controller ports
            for port in ctrl.findall("./OBJECT[@name='ports']"):
                port_attrs = {'i': 'port', 't': 'port-type', 's': 'status-numeric', 'h': 'health-numeric',
                              'ps': 'actual-speed'}
                port_data = get_common_attr(port, port_attrs)
                port_data['sfp'] = int(port.find(".//PROPERTY[@name='sfp-present-numeric']").text)
                # Before 1050/2050 API has no numeric property for sfp-status
                sfp_status_map = {"Not compatible": '0', "Incorrect protocol": '1', "Not present": '2', "OK": '3'}
                sfp_status = port.find(".//PROPERTY[@name='sfp-status']")
                sfp_status_num = port.find(".//PROPERTY[@name='sfp-status-numeric']")
                port_data['ss'] = int(sfp_status_num.text) if sfp_status_num else int(sfp_status_map[sfp_status.text])
                sdata['ports'].append(port_data)

        # Power Supplies
        for ps in en.findall("./OBJECT[@name='power-supplies']"):
            ps_attrs = {'i': 'durable-id', 'p': 'position-numeric', 's': 'status-numeric', 'h': 'health-numeric',
                        '12v': 'dc12v', '5v': 'dc5v', '33v': 'dc33v', '12i': 'dc12i', '5i': 'dc5i'}
            ps_data = get_common_attr(ps, ps_attrs)
            sdata['ps'].append(ps_data)

        # Fans
        for fan in en.findall(".//OBJECT[@name='fan-details']"):
            fan_attrs = {'i': 'durable-id', 'p': 'position-numeric', 's': 'status-numeric', 'h': 'health-numeric',
                         'sp': 'speed', 'ss': 'status-ses-numeric'}
            fan_data = get_common_attr(fan, fan_attrs)
            # Extended status in hex32 or uint32
            fan_estatus = fan.find("./PROPERTY[@name='extended-status']")
            fan_data['sx'] = int(fan_estatus.text, 16) if fan_estatus.get('type') == 'hex32' else int(fan_estatus.text)
            sdata['fans'].append(fan_data)

    # Pools and Disk groups
    for pool in xml.findall("./OBJECT[@name='pools']"):
        pool_attrs = {'i': 'name', 'tp': 'storage-type-numeric', 'sn': 'serial-number', 'ts': 'total-size-numeric',
                      'ta': 'total-avail-numeric', 'h': 'health-numeric', 'o': 'owner-numeric',
                      'op': 'preferred-owner-numeric'}
        pool_data = get_common_attr(pool, pool_attrs)
        sdata['pools'].append(pool_data)

        # Disk groups
        for dg in pool.findall("./OBJECT[@name='disk-group']"):
            dg_attrs = {'i': 'name', 'sz': 'size-numeric', 'fs': 'freespace-numeric', 'tp': 'storage-type',
                        'tr': 'storage-tier', 's': 'status-numeric', 'h': 'health-numeric', 'o': 'owner-numeric',
                        'op': 'preferred-owner-numeric', 'j': 'current-job-numeric'}
            dg_data = get_common_attr(dg, dg_attrs)
            dg_cur_job_pct = dg.find("./PROPERTY[@name='current-job-completion']").text
            # current job completion return None if job isn't running, replacing it with zero
            dg_data['jp'] = 0 if dg_cur_job_pct is None else int(dg_cur_job_pct.rstrip('%'))
            sdata['dg'].append(dg_data)

    # Virtual disks
    for vd in xml.findall("./OBJECT[@name='virtual-disk']"):
        vd_attrs = {'i': 'name', 'sn': 'serial-number', 'sz': 'size-numeric', 'fs': 'freespace-numeric',
                    's': 'status-numeric', 'h': 'health-numeric', 'j': 'current-job-numeric'}
        vd_data = get_common_attr(vd, vd_attrs)
        vd_cur_job_pct = vd.find("./PROPERTY[@name='current-job-completion']").text
        # current job completion return None if job isn't running, replacing it with zero
        vd_data['jp'] = 0 if vd_cur_job_pct is None else int(vd_cur_job_pct.rstrip('%'))
        sdata['vd'].append(vd_data)

    # Physical drives
    for drive in xml.findall("./OBJECT[@basetype='drives']"):
        dr_attrs = {'i': 'location', 'a': 'architecture-numeric', 'h': 'health-numeric', 't': 'temperature-numeric',
                    'ts': 'temperature-status-numeric', 'j': 'job-running-numeric', 'p': 'power-on-hours'}
        dr_data = get_common_attr(drive, dr_attrs)

        # API doesn't contains numeric value for drives 'status' property
        dr_status_map = {'Up': 0, 'Spun Down': 1, 'Warning:': 2, 'Error': 3, 'Unknown': 4, 'Not Present': 5,
                         'Unrecoverable': 6, 'Unavailable': 7, 'Unsupported': 8}
        dr_data['s'] = dr_status_map[drive.find("./PROPERTY[@name='status']").text]
        # Return SSD disk live remaining
        if dr_data['a'] == 0:
            dr_data['ll'] = int(drive.find("./PROPERTY[@name='ssd-life-left-numeric']").text)
        sdata['drives'].append(dr_data)
    return json.dumps(sdata, separators=(',', ':'), indent=pretty)


def expand_dict(init_dict) -> dict:
    """Expand dict keys to full names

    :param init_dict: Initial dict
    :return: Dictionary with fully expanded key names
    """

    # Match dict for print output in human readable format
    m = {'h': 'health', 's': 'status', 'ow': 'owner', 'owp': 'owner-preferred', 't': 'temperature',
         'ts': 'temperature-status', 'cj': 'current-job', 'poh': 'power-on-hours', 'rs': 'redundancy-status',
         'fw': 'firmware-version', 'sp': 'speed', 'ps': 'port-status', 'ss': 'sfp-status',
         'fh': 'flash-health', 'fs': 'flash-status', '12v': 'power-12v', '5v': 'power-5v',
         '33v': 'power-33v', '12i': 'power-12i', '5i': 'power-5i', 'io': 'iops', 'cpu': 'cpu-load',
         'cjp': 'current-job-completion'
         }

    result = {}
    for compid, metrics in init_dict.items():
        h_metrics = {}
        for key in metrics.keys():
            try:
                h_metrics[m[key]] = metrics[key]
            except KeyError:
                print(f'ERROR: cannot find name map for "{key}"')
                h_metrics[key] = metrics[key]
        result[compid] = h_metrics
    return result


if __name__ == '__main__':
    VERSION = '0.7super'
    MSA_PARTS = ('disks', 'vdisks', 'controllers', 'enclosures', 'fans', 'power-supplies', 'ports', 'pools',
                 'disk-groups', 'volumes')

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

    # SUPER script command
    super_parser = subparsers.add_parser('super', help='Experimental: Return all possible data with one JSON doc')
    super_parser.add_argument('msa', type=str, help='MSA connection address (DNS name or IP)')
    args = main_parser.parse_args()

    API_VERSION = args.api
    TMP_DIR = args.tmp_dir
    CACHE_DB = TMP_DIR.rstrip('/') + '/zbx-hpmsa.cache.db'

    if args.command in ('lld', 'full', 'super'):
        SAVE_XML = args.save_xml
        USE_SSL = args.ssl in ('direct', 'verify')
        VERIFY_SSL = args.ssl == 'verify'
        MSA_USERNAME = args.username
        MSA_PASSWORD = args.password
        to_pretty = 2 if args.pretty else None

        # (IP, DNS)
        IS_IP = all(elem.isdigit() for elem in args.msa.split('.'))
        MSA_CONNECT = args.msa if IS_IP else gethostbyname(args.msa), args.msa

        if args.login_file is not None:
            CRED_HASH = make_cred_hash(args.login_file, isfile=True)
        else:
            CRED_HASH = make_cred_hash('_'.join([MSA_USERNAME, MSA_PASSWORD]))
        skey = get_skey(MSA_CONNECT, CRED_HASH)

        if args.command == 'lld':
            print(make_lld(MSA_CONNECT, args.part, skey, to_pretty))
        elif args.command == 'full':
            print(get_full(MSA_CONNECT, args.part, skey, to_pretty, args.human))
        elif args.command == 'super':
            print(get_super(MSA_CONNECT, skey, to_pretty))
    elif args.command == 'install':
        if args.reinstall:
            print("Removing '{}' and '{}'".format(CACHE_DB, TMP_DIR))
            os.remove(CACHE_DB)
            os.rmdir(TMP_DIR)
            install_script(TMP_DIR, args.group)
        else:
            install_script(TMP_DIR, args.group)
    elif args.command == 'cache':
        if args.show:
            display_cache()
        elif args.drop:
            sql_cmd('DELETE FROM skey_cache;')
        else:
            display_cache()
