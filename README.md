# genwg
genwg is a wireguard and isc bind9 configuration generator with faketcp support
and system resolver awareness.

## features
- wireguard "server" and "client" peer configuration generation.
- allowing peers to utilize faketcp via udp2raw. __(linux and android only)__
- android support for upd2raw without `wg-quick`'s `PreUp`/`PreDown` hooks which
  do not exist in the android implementation.
- generation of local plug and play bind9 `A` and `PTR` zones that reference the
  client peers for querying a list of all clients via `dig axfr .local_zone
  @<ip.of.server.iface>` and for seamless DNS resoluton via `resolv.conf`
  `search`.
- allowing clients to incorporate the server's recursive DNS resolver into their
  local bind9 instance so that they get to keep their local zones while 
  forwarding the root zone requests to the wireguard server to prevent leaks.
  __(linux only)__
- yaml dump of the state after execution.

as Termux and alike do not have `udp2raw` packaged, you can find a build
script and a prebuilt aarch64 elf binary.

## installation
```sh
git clone --depth=1 https://github.com/gottaeat/genwg
cd genwg/
pip install .
```

## configuration
### specification
#### servers
| key           | necessity | description                                                                                                                |
|---------------|-----------|----------------------------------------------------------------------------------------------------------------------------|
| name          | required  | `str` name for the interface                                                                                               |
| priv          | optional  | `str` wireguard private key for the server peer, will be generated if none provided                                        |
| ip            | required  | `str` public ip address of the wireguard server peer                                                                       |
| port          | required  | `int` port for the server peer to listen on                                                                                |
| net           | required  | `str` vpn subnet in cidr notation                                                                                          |
| mtu           | required  | `int` mtu value for the interface: max 1340 for faketcp and 1460 for udp                                                   |
| extra_address | optional  | `str` extra /32's to be appended to the Address line of the server peer and to the AllowedIPs of the clients that opted in |
| extra_allowed | optional  | `str` extra non-/32 v4's to be added to the AllowedIPs of the clients in the configuration of the client itself            |
| named         | optional  | look below                                                                                                                 |
| udp2raw       | optional  | look below                                                                                                                 |

__WARNING__: if the same v4 that resides within `extra_allowed` of a server
exist in the `extra_allowed` of the client, this network will not be added to
that client's network, and when dumping back the yaml, this v4 will be removed
from the server's `extra_allowed`.

#### named
| key      | necessity | description |
|----------|-----------|-------------|
| hostname | required  | `str` value to be set as the name for the .1 of the vpn subnet in A and PTR records
| conf_dir | required  | `str` path where `named.conf` on the server peer lives, e.g. `/etc/bind`

#### udp2raw
| key    | necessity | description                                                |
|--------|-----------|------------------------------------------------------------|
| secret | optional  | `str` `udp2raw` secret, will be generated if none provided |
| port   | required  | `int` port for `udp2raw` to listen on                      |

#### clients
| key              | necessity                                 | description                                                                                                                                                       |
|------------------|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name             | required                                  | `str` name for the client peer, only matters when server configuration requested bind9 zones to be generated                                                      |
| priv             | optional                                  | `str` wireguard private key for the client peer, will be generated if none provided                                                                               |
| wg_handled_dns   | optional                                  | `bool` if set to true, the DNS ini key will be added and set to the internal ip of the wireguard interface for wg-quick to handle it in the platform specific way |
| bind             | optional                                  | `bool` if set to true, client configuration will have `PreUp` and `PreDown` hooks added to it to have the root zone forwarded to the server peer                  |
| root_zone_file   | required if `bind`                        | `str` path to the file that contains the root hints                                                                                                               |
| udp2raw_log_path | required if `server.udp2raw`              | `str` path to dump the udp2raw stdin and stderr                                                                                                                   |
| android          | optional                                  | `str` declare client an android device                                                                                                                            |
| wgquick_path     | required if `android` && `server.udp2raw` | `str` path to the `wg-quick` binary                                                                                                                               |
| udp2raw_path     | required if `android` && `server.udp2raw` | `str` path to the `udp2raw` binary                                                                                                                                |

__WARNING__: doing wireguard over faketcp on android may require root privileges depending on your device firmware.

### example
```yml
servers:
- name:  wg0
  ip: 1.1.1.1
  port: 51820
  net: 10.0.0.0/24
  mtu: 1420
  named:
    hostname: debian12
    conf_dir: /etc/bind
  extra_address:
    - 192.168.1.2/32
  clients:
    - name: myrouter
      append_extra: true
      extra_allowed:
        - 192.168.1.0/24
    - name: mylinuxdesktop
      bind: true
      root_zone_file: /var/named/zone/root-nov6
    - name: myphone

- name: wg0raw
  ip: 1.1.1.1
  port: 51821
  net: 10.0.1.0/24
  mtu: 1340
  extra_allowed:
    - 10.0.0.0/24
  named:
    hostname: debian12raw
    conf_dir: /etc/bind
  udp2raw:
    port: 6666
  clients:
  - name: corponetlaptop
    bind: true
    root_zone_file: /var/named/zone/root-nov6
    udp2raw_log_path: /var/log/udp2raw.log
  - name: myphone
    udp2raw_log_path: ./udp2raw.log
    android: true
    wgquick_path: /system/xbin/wg-quick
    udp2raw_path: /data/data/com.termux/files/home/udp2raw

- name: wg0guest
  ip: 1.1.1.1
  port: 51822
  net: 10.0.2.0/24
  mtu: 1420
  clients:
    - name: johnguest
```

## usage
```sh
genwg -c /path/to/genwg.yml
```
