# zbx-hpmsa
Utility for retrieve hardware info from HPE MSA storage via XML API for Zabbix Monitoring Platform.  
Zabbix Share page: https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api  
Also you can contact me with Telegram: @asand3r

zbx-hpmsa provides ability to make Low Level Discovery (LLD) of HPE MSA storage components via it's XML API and retrieve many of some other metrics like health statuses, temperature etc.
Program wrote with Python 3.7, but works fine with Python 3.4 from EPEL.

**Latest stable versions:** 0.6.8

__Please, read [Requirements and Installation](https://github.com/asand3r/zbx-hpmsa/wiki/Requirements-and-Installation) section on Wiki page before use.__  

## v0.5 vs v0.6
Hi, everyone. =)  
Yeap, I made it again and broke compatibility between versions. Sorry. =) Actually, I've increased version number not because of new functionalilty but because of new syntax. Hope, it's good desition and will be more comfortable in usage.  
Unlike previous versions, where we have one-level arguments for whole program, in v0.6 I've added five main positional arguments with their own parameter list:
 - lld
 > Still do Low-Level Discovery tasks for list of HPE MSA parts.
 - full
 > Retrieves all important (in my opinion) metrics from MSA in JSON object.
 - health
 > Shows health status for one MSA part, like controller, disk, disk-group etc (this option will be removed in v0.7 I think).
 - install
 > Executes some preparation tasks, like creating directory for cache db with all needed privileges.
 > It must be executed one time before utility usage.
 - cache
 > Here we check our cache and drop it, if we want.

Every command have own help (--help), so I'll not describe it here. Nevertheless, you should look at new examples and the relevant wiki page. Oh, one more - '--https' option was renamed to '--ssl' like more short variant (we've saved two chars!). =)

For now, item keys looks more pretty. Look at next examples:
```bash
zbx-hpmsa.py["-m", "{HOST.CONN}", "-d", "-c", "controllers"]  vs  zbx-hpmsa.py["lld", "{HOST.CONN}", "controllers"]  
zbx-hpmsa.py["-m", "{HOST.CONN}", "-g", "1.24", "-c", "disks"]  vs  zbx-hpmsa.py["health", "{HOST.CONN}", "disks", "1.24"]  
zbx-hpmsa.py["-m", "{HOST.CONN}", "-g", "full", "-c", "disk-groups"]  vs  zbx-hpmsa.py["full", "{HOST.CONN}", "disks-groups"]  
```
---

## Dependencies
 - requests
 - sqlite3

## Feautres  
**Common:**
 - [x] Bulk requests for dependent items (Zabbix 3.4+)
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

## TODO  
- [ ] Add correct processing of round-robin DNS records

## Usage
You can find more examples on Wiki page, but I placed some cases here too. Be noticed - syntax of v0.5 and v0.6 differs!  
- LLD of enclosures, controllers, virtual disks and physical disks:  
Before v0.6:  
```bash
[user@server ~] # ./zbx-hpmsa.py --discovery --msa 10.0.0.1 --component vdisks
{"data":[{"{#VDISKNAME}":"vDisk01"},{"{#VDISKNAME}":"vDisk02"}]}
```
With v0.6:
```bash
[user@server ~] # ./zbx-hpmsa.py lld 10.0.0.1 vdisks
{"data":[{"{#VDISKNAME}":"vDisk01"},{"{#VDISKNAME}":"vDisk02"}]}
```

- Request health status of one component. E.g. disk '1.1':  
Before v0.6:  
```bash
[user@server ~] # ./zbx-hpmsa.py --msa 10.0.0.1 --component disks --get 1.1
OK
```
With v0.6:

```bash
[user@server ~] # ./zbx-hpmsa.py health 10.0.0.1 disks 1.1
OK
```
- Request full available data in JSON. E.g. all disks or controller 'A':  
Before v0.6:
```bash
[user@server ~] # ./zbx-hpmsa.py --msa 10.0.0.1 --component disks --get-health full
{"1.1":{"health":"OK","health-num":"0","error":"0","temperature":"25","power-on-hours":"26094"}, ... }
[user@server ~] # ./zbx-hpmsa.py --msa 10.0.0.1 --component controllers --get-health full
{"A":{"health":"OK","health-num":"0","status":"Operational","status-num":"0","redundancy":"Redundant","redundancy-num":"2","flash-health":"OK","flash-health-num":"0","flash-status":"Installed","flash-status-num":"1"}, ... }
```
With v0.6:
```bash
[user@server ~] # ./zbx-hpmsa.py full 10.0.0.1 disks
{"1.1":{"health":"OK","health-num":"0","error":"0","temperature":"25","power-on-hours":"26094"}, ... }
[user@server ~] # ./zbx-hpmsa.py full 10.0.0.1 controllers
{"A":{"health":"OK","health-num":"0","status":"Operational","status-num":"0","redundancy":"Redundant","redundancy-num":"2","flash-health":"OK","flash-health-num":"0","flash-status":"Installed","flash-status-num":"1"}, ... }
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
