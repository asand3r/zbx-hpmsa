# zbx-hpmsa
Utility for retrieve hardware info from HPE MSA storage via XML API for Zabbix Monitoring Platform.  
Zabbix Share page: https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api  
Also you can contact me with Telegram: @asand3r

zbx-hpmsa provides ability to make Low Level Discovery (LLD) of HPE MSA storage components via it's XML API and retrieve many of some other metrics like health statuses, temperature etc.
Program wrote with Python 3.7, but works fine with Python 3.4 from EPEL.

**Latest stable versions:** 0.7

__Please, read [Requirements and Installation](https://github.com/asand3r/zbx-hpmsa/wiki/Requirements-and-Installation) section on Wiki page before use.__  

## v0.6 vs v0.7
There are a couple of important changes in v0.7 of the script:  
  - Removed 'health' argument. It was used for working with old Zabbix versions, which doesn't support JSONPath preprocessing (like 3.0 and 3.2). So, version 0.7 supports only Zabbix 4.0 and 4.2;
  - Version 0.7 breaks compatibility with template distributed for version 0.6.x. Now, master item contains JSON with shorten key names.  
E.g. version 0.6.8 outpul was:  
```bash
[root@server ~]# ./zbx-hpmsa_v0.6.8.py full storage-ip-address fans
{"fan_1.1":{"health-num":"0","status-num":"0","speed":"3770"},"fan_1.2":{"health-num":"0","status-num":"0","speed":"3910"}}
```
And from 0.7 it becomes like that:
```bash
[root@server ~]# ./zbx-hpmsa_v0.7.py full storage-ip-address fans
{"fan_1.1":{"h":"0","s":"0","sp":"3910"},"fan_1.2":{"h":"0","s":"0","sp":"3920"}} 
```
I hope it will reduce total received bytes by Zabbix database.  

  - Also, version 0.7 contains two new cli arguments: '--pretty' and '--human'. The first one is for printing JSON with linebeaks and the second for translate shorten JSON keys to full human readable names.
```bash
[root@server ~]# ./zbx-hpmsa_v0.7.py --pretty full storage-ip-address fans
{
  "fan_1.1":{
    "h":"0",
    "s":"0",
    "sp":"3900"
  },
  "fan_1.2":{
    "h":"0",
    "s":"0",
    "sp":"3930"
  }
}
[root@server ~]# ./zbx-hpmsa_v0.7.py --human --pretty full storage-ip-address fans
{
  "fan_1.1":{
    "health":"0",
    "status":"0",
    "speed":"3890"
  },
  "fan_1.2":{
    "health":"0",
    "status":"0",
    "speed":"3930"
  }
}
```
---

## Dependencies
 - requests
 - sqlite3

## Feautres  
**Common:**
 - [x] Bulk requests for dependent items (Zabbix 4.0+)
 - [x] HTTPS support
 - [x] Login cache (SQLite3)
 - [x] 'install' argument to prepare script to work

**LLD, health check and full data in JSON:**
 - [x] Physical disks
 - [x] Virtual disks
 - [x] Controllers
 - [x] Enclosures
 - [x] Ports
 - [x] Pools
 - [x] Disk groups
 - [x] Power supplies
 - [x] Fans
 - [x] Volumes

## Usage
You can find more examples on Wiki page, but I placed some cases here too.   
- LLD of enclosures, controllers, virtual disks and physical disks:  
```bash
[root@server ~] # ./zbx-hpmsa.py lld 10.0.0.1 volumes
{"data":[{"{#VOLUME.ID}":"Test_Volume","{#VOLUME.SN}":"00c0ff2896a400008fb7265a01000000","{#VOLUME.TYPE}":"standard"}}
```

- Request full available data in JSON. E.g. all disks:  
```bash
[root@server ~] # ./zbx-hpmsa.py full 10.0.0.1 disks
{"1.1":{"h":"0","t":"25","ts":"1","cj":"0","poh":"15050"},"1.2":{"h":"0","t":"25","ts":"1","cj":"0","poh":"15050"}, ... }
```

## Zabbix templates
In addition I've attached preconfigured Zabbix Templates here, so you can use them in your environment and build your own template based on it.  
Templates using LLD functionality and {HOST.CONN} macro to determine HTTP(S) connection URL, so make sure that it points to right DNS name or IP and your MSA has HTTP(S) protocol enabled.  
Also template expects what MSA storage has default user with default password - **'monitor'@'!monitor'**, but if it isn't true - correct it with '-u' and '-p' or '-f|--login-file' options.  
If you want to use HTTPS, you must correct template and be sure what {HOST.CONN} macro contains FQDN. By the way, look at relevant Wiki page for HTTPS support.  
Started with version v0.5.4 I've attached new template file for Zabbix 4.0, which using dependent items functionality and can retrieve much more metrics from storage than earlier versions. Check [Wiki](https://github.com/asand3r/zbx-hpmsa/wiki/Zabbix-4.0-Templates) to read more about it or if you speak russian look at my post on [habr.com](https://habr.com/post/419221/).

Have fun and don't forget to rate it on [share.zabbix.com](https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api) if you like it. =)

**Tested with**:  
HP MSA P2000 G3, HP MSA 2040, HP MSA 2050, HP MSA2324FC (2000 G2 series, I think, will works too)

**Known Issues**:
- Using '--https verify' with round-robin DNS name doesn't works correctly. It may give you the "ERROR: -10027", that means the user in not recongnized on the system. It happens because of session key was given from one MSA controller, but the script tries to establish connections the other one. The option '--https direct|--ssl direct' will works fine, so you can try to use it instead. I haven't full solution right now, so just don't using it so. =)
