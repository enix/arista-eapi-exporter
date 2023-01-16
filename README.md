# Arista eAPI Exporter

[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Brought by Enix](https://img.shields.io/badge/Brought%20to%20you%20by-ENIX-%23377dff?labelColor=888&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBAkQIg/iouK/AAABZ0lEQVQY0yXBPU8TYQDA8f/zcu1RSDltKliD0BKNECYZmpjgIAOLiYtubn4EJxI/AImzg3E1+AGcYDIMJA7lxQQQQRAiSSFG2l457+655x4Gfz8B45zwipWJ8rPCQ0g3+p9Pj+AlHxHjnLHAbvPW2+GmLoBN+9/+vNlfGeU2Auokd8Y+VeYk/zk6O2fP9fcO8hGpN/TUbxpiUhJiEorTgy+6hUlU5N1flK+9oIJHiKNCkb5wMyOFw3V9o+zN69o0Exg6ePh4/GKr6s0H72Tc67YsdXbZ5gENNjmigaXbMj0tzEWrZNtqigva5NxjhFP6Wfw1N1pjqpFaZQ7FAY6An6zxTzHs0BGqY/NQSnxSBD6WkDRTf3O0wG2Ztl/7jaQEnGNxZMdy2yET/B2xfGlDagQE1OgRRvL93UOHqhLnesPKqJ4NxLLn2unJgVka/HBpbiIARlHFq1n/cWlMZMne1ZfyD5M/Aa4BiyGSwP4Jl3UAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjAtMDQtMDlUMTQ6MzQ6MTUrMDI6MDDBq8/nAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIwLTA0LTA5VDE0OjM0OjE1KzAyOjAwsPZ3WwAAAABJRU5ErkJggg==)](https://enix.io)

A Prometheus exporter for Arista's EOS that uses the eAPI and can be easily extended to support more metrics. 

## Quick setup using Docker on Arista devices

You can start the exporter directly on the Arista switch using the built-in Docker daemon integration called [*container-manager*](https://aristanetworks.force.com/AristaCommunity/s/article/managing-containers-on-eos-container-manager) and the publicly available image of this exporter:

```
container-manager
   container exporter
      image enix/arista-eapi-exporter:latest
      on-boot
      options -p 9100:9100
      command single -s ip -k -u username -p password -l tenant customer1 -l role spine

management api http-commands
   no shutdown
```

Unfortunately, the password used to connect to the eAPI will appear in plaintext in the config, so it may be best to dedicate a user with a read-only role (such as `network-operator`).

You should also customize the host labels configured using `-l name value`.

Please keep in mind that these commands enable an HTTPS API server that will be reachable from outside your switch (if you do not set up any ACL).
There are other options (namely, UNIX socket and local HTTP server) but they pose other issues ([see below](#unix-socket)).

## How does this compare to ocprometheus or other exporters

When it comes to setting up a Prometheus exporter for Arista switches, there are several other
options, even some from Arista itself (such as [ocprometheus](https://github.com/aristanetworks/goarista/tree/master/cmd/ocprometheus)) you can consider.
The main goal this exporter tries to achieve is to allow users to customize by themselves which metrics
is gathered from the target, without having to fork the repository and alter the code.

The use-case may be to add a metric to retrieve an obscure counter from a rarely-used
feature, or to remove unneeded metrics to reduce the load on both the Arista device and the
Prometheus server.

This design goal drove two main technical choices for this exporter :
- Use the eAPI, rather than gNMI or even the SysDB directly. The eAPI is largely documented
and very easy to tinker with.
- Use a separated "configuration" YAML file for the eAPI-to-metrics translation.

See [API commands and metrics](#api-commands-and-metrics) for more details.

Also, Docker is officially supported for deploying the exporter in a matter of minutes (if you do not need any customization).

## Usage and modes of operation

```
$ ./arista-eapi-exporter.py -h
usage: arista-eapi-exporter.py [-h] [-a API_COMMANDS] [-d] {multiple,single} ...

Launch a Prometheus Exporter exposing metrics from Arista EOS devices via their eAPI.

positional arguments:
  {multiple,single}

options:
  -h, --help            show this help message and exit
  -a API_COMMANDS, --api-commands API_COMMANDS
                        YAML config file containing API commands to execute and what metrics to export
  -d, --debug           Display debugging statements
```

The correspondance between commands passed to the eAPI and exposed by the exporter can be configured in the YAML file passed
to `--api-commands`. There is [a dedicated section](#api-commands-and-metrics) on this page of how this file is structured.

The provided `api_commands.yaml` contains a decent starting set of metrics that can be easily customized if needed.
It is the one embedded in the publicly available Docker images.

This exporter can operate in two different modes of operation : *multiple* and *single* 

### Multiple

```
$ ./arista-eapi-exporter.py multiple -h
usage: arista-eapi-exporter.py multiple [-h] [-c CONFIG]

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        YAML config file containing targets and credentials
```

In multiple mode, the exporter can poll a list of targets configured in a YAML file passed as `--config`.
Here is an example :

```yaml
global:
  listen_port: 9100  # TCP port the exporter will bind to and expose the HTTP interface
  interval: 300  # Polling interval, in seconds
  custom_host_labels:  # Custom host-level labels, see below
    - tenant
    - role
defaults:
  username: prometheus  # The user to use to connect to the eAPI
  password: supersecurep4ssw0rd  # The password to use to connect to the eAPI
  port: 443  # HTTPS port where the eAPI listens
  allow_insecure: false  # Allow self-signed API certificate
  timeout: 5  # API query timeout, in seconds
targets:  # List of Arista devices to query
  - name: router-1.example.com  # Name of the device. Set to `null` to dynamically retrieve the name.
    hostname: 198.51.100.1  # IP or hostname to connect to. If absent, `name` will be used
    tenant: customer1  # Value of the custom host-level label `tenant`
    role: spine  # Value of the custom host-level label `role`
```

#### Defaults

The following parameters can be defined at target level or in the `defaults` section :
  - `username`
  - `password`
  - `port`
  - `allow_insecure`
  - `timeout`

They are all mandatory.

#### Custom host labels

This exporter supports adding arbitrary labels to metrics, with values identical for all metrics of a single host. The labels' names must be defined in `global.custom_host_labels`, and their values must be set either in each target or in the `defaults`.

Custom host labels is the appropriate place to add host metadata such as a `tenant`, or a device role such as `spine` or `leaf`. This is useful when later designing alerting rules for instance.

The above custom labels would produce something like this :
```
arista_show_version_memFree{hostname="198.51.100.1",name="router-1.example.com",role="spine",tenant="customer1"} 6.08906e+06
```

`name` and `hostname` are automatically added as labels.

### Single

```
$ ./arista-eapi-exporter.py single -h
usage: arista-eapi-exporter.py single [-h] -s {unix,ip} [-t TARGET] [-u USERNAME] [-p PASSWORD] [-k] [-w TIMEOUT] [-i INTERVAL] [--listen-port LISTEN_PORT] [-l NAME VALUE]

options:
  -h, --help            show this help message and exit
  -s {unix,ip}, --socket {unix,ip}
                        Wether to use UNIX or IP socket
  -t TARGET, --target TARGET
                        Target URL. Defaults to 'https://172.17.0.1/command-api' or 'http+unix://%2Fvar%2Frun%2Fcommand-api.sock/command-api' depending on the socket type.
  -u USERNAME, --username USERNAME
                        Username to use when connecting using an IP socket. EOS ignores credentials when using an UNIX socket.
  -p PASSWORD, --password PASSWORD
                        Password to use when connecting using an IP socket. EOS ignores credentials when using an UNIX socket.
  -k, --allow-insecure  Do not perform a strict check of HTTPS certificate when using IP socket with an HTTPS URL.
  -w TIMEOUT, --timeout TIMEOUT
                        Seconds to wait when performing HTTP requests to the API. Defaults to 5.
  -i INTERVAL, --interval INTERVAL
                        Interval, in seconds, to use for refreshing all metrics on all targets. Defaults to 300 (5 minutes).
  --listen-port LISTEN_PORT
                        HTTP port where the exporter will bind. Defaults to 9100.
  -l NAME VALUE, --label NAME VALUE
                        Additional label to export at host level (i.e. on all metrics). Can be repeated.
```

In single mode, the exporter only polls one Arista device, but all the connection parameters can be provided using CLI arguments. This is useful if you want to deploy the exporter directly on your switches, leveraging Arista's Linux platform or Docker integration.

In this mode, the exporter can connect to the eAPI using either a classic IP socket, or an UNIX socket

#### IP socket

When using an IP socket, the target URL need to be of the form `http[s]:IP_OR_FQDN[:PORT]/command-api`. The default is `https://172.17.0.1/command-api` because this is the default IP of the switch when starting the exporter using docker. But any IP or FQDN and port where the switch is reachable, including `127.0.0.1`, is fine.

#### UNIX socket

WARNING: MAY BE INSECURE

The exporter can also reach the eAPI using an UNIX socket. In this mode, the target URL must be of the form `http+unix://%2Fpath%2Fto%2Fthe%2Fsocket/command-api` with a default of `http+unix://%2Fvar%2Frun%2Fcommand-api.sock/command-api` (which is the default location of the socket when enabled in EOS).

Be aware that in this mode, EOS does not -by design- check authorization or even the validity of the credentials provided with `-u` and `-p`. This means that any compromised code would be granted read/write access, regardless of the fact that the user account has a read-only role. Use with caution.
Note that this is the same problem with the "Local HTTP server" enabled with `protocol http localhost`.

To enable (only) the eAPI over UNIX socket, configure your device like this :

```
management api http-commands
   no protocol https
   protocol unix-socket
   no shutdown
```

If you run the exporter using the integrated Docker engine, `container-manager`, you will need to add `-v /var/run/command-api.sock:/var/run/command-api.sock` to the `options` config directive of your container to bind mount the socket into the Docker container.

## API commands and metrics

Every `show` command passed to the eAPI and its resulting Prometheus metrics is defined in the YAML files passed as `-a` or `--api-commands` (by default the exporter will look in `/etc/arista-eapi-exporter/api_commands.yaml`).

All commands present in this file are queried in a single API call.

Each metric is defined as an element of the dictionary `commands`, as such :

```yaml
commands:
  show interfaces:  # 'show' command passed to the eAPI
    type: multiple  # Type of the command, or more accurately the type of the returned output
    lookup_keys: interfaces  # Specific to type `multiple`, see below
    metrics:  # Values to extract from the JSON response and expose as a Prometheus metric
      - name: bandwidth
    labels:  # Values to extract from the JSON response and expose as metric labels
      - name: name
        prom_name: interface_name
      - name: description
```

You can look at what the eAPI response looks like directly from the device's CLI by appending `| json` to your show command, e.g. `show interfaces | json`.

Alternatively, if the eAPI is reachable from your computer, you can browse the eAPI and have a look at the returned JSON data using the built-in API explorer by visiting `https://SWITCH_IP/explorer.html`.

However, please keep in mind that this exporter uses the latest revision of the eAPI command outputs.
It is the same as the `| json` CLI output but if you use the explorer (or craft your own API requests),
you need to set `version` to `latest` instead of the default `1`.


### Command types

#### Flat

Some commands return information in a "flat" way, i.e. the result is a dictionary where each direct element is a (potential) metric.

Here is an example with a `show version` from a vEOS-lab device:

```json
{
    "memTotal": 8116968,
    "uptime": 9449.91,
    "modelName": "vEOS",
    "internalVersion": "4.26.0.1F-21994874.42601F",
    "mfgName": "",
    "serialNumber": "",
    "systemMacAddress": "0c:30:e5:b2:61:61",
    "bootupTimestamp": 1673262120,
    "memFree": 6100428,
    "version": "4.26.0.1F",
    "configMacAddress": "00:00:00:00:00:00",
    "isIntlVersion": false,
    "internalBuildId": "e41b7ab2-f5ed-45cb-ba9c-f320cb81332f",
    "hardwareRevision": "",
    "hwMacAddress": "00:00:00:00:00:00",
    "architecture": "i686"
}
```

The corresponding *API command* would be :

```yaml
commands:
  show version:
    type: flat
    metrics:
      - name: memFree
      - name: memTotal
```

#### Table

Some commands, often displayed as a table in the CLI, return useful information in a list such as `show hardware capacity`

```json
{
    "tables": [
        {
            "highWatermark": 1898,
            "used": 1884,
            "usedPercent": 22,
            "committed": 0,
            "table": "Routing",
            "chip": "Jericho",
            "maxLimit": 8192,
            "feature": "Resource1",
            "free": 6308
        },
        {
            "highWatermark": 749276,
            "used": 747163,
            "usedPercent": 95,
            "committed": 0,
            "table": "LEM",
            "chip": "Jericho0",
            "maxLimit": 786432,
            "feature": "",
            "free": 39269
        }
    ]
}
```

The corresponding *API command* looks like this :

```yaml
  show hardware capacity:
    type: table
    lookup_key: tables
    metrics:
      - name: used
      - name: maxLimit
      - name: highWatermark
    labels:
      - name: table
      - name: feature
      - name: chip
```
The list is contained in a dictionary item, so the exporter expects a string `lookup_key` to know where to find it.

#### Multiple

Some commands return information as a dictionary of elements such as interfaces, VLANs, etc.
These can be nested, as in `show ip bgp summary`:

```json
{
    "vrfs": {
        "default": {
            "routerId": "192.168.1.254",
            "peers": {
                "192.168.1.2": {
                    "prefixReceived": 0,
                    "msgSent": 0,
                    "inMsgQueue": 0,
                    "underMaintenance": false,
                    "prefixInBest": 0,
                    "upDownTime": 1673370907.809562,
                    "version": 4,
                    "msgReceived": 0,
                    "prefixAccepted": 0,
                    "peerState": "Active",
                    "outMsgQueue": 0,
                    "prefixInBestEcmp": 0,
                    "asn": "1234"
                },
                "192.168.1.1": {
                    "prefixReceived": 0,
                    "msgSent": 0,
                    "inMsgQueue": 0,
                    "underMaintenance": false,
                    "prefixInBest": 0,
                    "upDownTime": 1673370907.806195,
                    "version": 4,
                    "msgReceived": 0,
                    "prefixAccepted": 0,
                    "peerState": "Active",
                    "outMsgQueue": 0,
                    "prefixInBestEcmp": 0,
                    "asn": "1234"
                }
            },
            "vrf": "default",
            "asn": "1234"
        }
    }
}
```

The corresponding *API command* looks like this :

```yaml
commands:
  show ip bgp summary:
    type: multiple
    lookup_keys: ['vrfs', 'peers']
    metrics:
      - name: prefixReceived
      - name: prefixAccepted
    labels:
      - name: version
      - name: asn
      - name: peers
        prom_name: peer
        special: metadata
      - name: vrfs
        prom_name: vrf
        special: metadata
```

A command of type `multiple` expects a string, or a list of strings in `lookup_keys`.
These keys will be used, in order, to descend into the nested dicts to the actual interesting data (here, peer statistics).
When doing that, each dictionary key will be accessible as a [label of type `special: metadata`](#special-metadata).

### Metric types

Metrics can have different types, depending on what they represent, and how they should be exported to prometheus.

#### Gauge (default)

```yaml
commands:
  show interfaces:
    type: multiple
    lookup_keys: interfaces
    metrics:
      - name: bandwidth
```

The default metric type, gauge, is suitable for a simple integer counter. It produces a prometheus metric of the same type.

#### Enum

```yaml
commands:
  show ip bgp summary:
    type: multiple
    lookup_keys: ['vrfs', 'peers']
    metrics:
      - name: peerState
        type: enum
        enum:
          - Established
          - OpenConfirm
          - NotNegotiated
          - OpenSent
          - Idle
          - Connect
          - Active
```

Suitable for an API response with text values. Creates a metric of type "Enum" (as in the `prometheus_client` python library, in reality it is a set of gauges), with fixed possible values defined in `enum`, effectively exposing one prometheus metric per possible value, one of whom has a value of `1.0` and the others `0.0`. However, most of the time, a `mapping` is more suitable.

An `enum` metric looks like this:
```
# HELP arista_show_ip_bgp_summary_peerState Arista EOS metric 'peerState' under 'show ip bgp summary'
# TYPE arista_show_ip_bgp_summary_peerState gauge
arista_show_ip_bgp_summary_peerState{arista_show_ip_bgp_summary_peerState="Established",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 0.0
arista_show_ip_bgp_summary_peerState{arista_show_ip_bgp_summary_peerState="OpenConfirm",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 0.0
arista_show_ip_bgp_summary_peerState{arista_show_ip_bgp_summary_peerState="NotNegotiated",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 0.0
arista_show_ip_bgp_summary_peerState{arista_show_ip_bgp_summary_peerState="OpenSent",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 0.0
arista_show_ip_bgp_summary_peerState{arista_show_ip_bgp_summary_peerState="Idle",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 0.0
arista_show_ip_bgp_summary_peerState{arista_show_ip_bgp_summary_peerState="Connect",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 0.0
arista_show_ip_bgp_summary_peerState{arista_show_ip_bgp_summary_peerState="Active",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 1.0
```

#### Mapping

```yaml
commands:
  show ip bgp summary:
    type: multiple
    lookup_keys: ['vrfs', 'peers']
    metrics:
      - name: peerState
        type: mapping
        mapping:
          Established: 0
          OpenConfirm: 1
          NotNegotiated: 2
          OpenSent: 3
          Idle: 4
          Connect: 5
          Active: 6
```

Also suitable for API response with text value, maybe easier than an `enum` to integrate into a Grafana dashboard, creates one metric of type Gauge, where each possible value is represented by a different integer. These text-to-integer mappings are defined in `mapping`.

To know every possible value of such metric, go to https://www.arista.com/en/support/software-download and look for a file named `CommandApiGuide.pdf` in your version of EOS (or one close to it).
You may also find the information in the documentation embedded into the eAPI explorer directly on your device.

A `mapping` metric looks like this:
```
# HELP arista_show_ip_bgp_summary_peerState Arista EOS metric 'peerState' under 'show ip bgp summary'
# TYPE arista_show_ip_bgp_summary_peerState gauge
arista_show_ip_bgp_summary_peerState{hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",vrf="default"} 6.0
```

#### Buckets

```yaml
  show ip route vrf all summary:
    type: multiple
    lookup_keys: vrfs
    metrics:
      - name: maskLen
        type: buckets
        bucket_name: prefix_length
```

Some data is spread out in a histogram kind of way. This is the case with the `maskLen` metric of `show ip route summary` 
which show number of routes spread out per mask length:

```json
{
    "vrfs": {
        "default": {
            "maskLen": {
                "8": 2,
                "31": 19,
                "32": 25
            }
        }
    }
}
```

Instead of going through every possible metric from `- name: maskLen.0` up to `- name: masklen.32`, a metric of type `buckets`
with a `bucket_name` will automatically produce metrics for every possible values, represented as labels, like this :

```
arista_show_ip_route_vrf_all_summary_maskLen{hostname="198.51.100.1",name="router-1.example.com",prefix_length="8"} 2.0
arista_show_ip_route_vrf_all_summary_maskLen{hostname="198.51.100.1",name="router-1.example.com",prefix_length="31"} 19.0
arista_show_ip_route_vrf_all_summary_maskLen{hostname="198.51.100.1",name="router-1.example.com",prefix_length="32"} 25.0
```

### Labels

#### prom_name

```yaml
commands:
  show interfaces:
    type: multiple
    lookup_keys: interfaces
    metrics:
      - name: bandwidth
    labels:
      - name: name
        prom_name: interface_name
      - name: description
```

Sometimes API response items destined to be used as label values can have non explicit or forbidden names (such as `name`), contain forbidden characters (such as `-`) or is just not suitable.
In that case, you can specify a `prom_name` besides the label's `name` to be used as the label name in the exported metrics.

In our example, the eAPI returns something like this :
```json
{
    "interfaces": {
        "Management1": {
            "bandwidth": 1000000000,
            "name": "Management1",
            "description": "OOB Access"
        }
    }
}
```

And the resulting metric :

```
arista_show_interfaces_bandwidth{description="OOB Access",hostname="198.51.100.1",interface_name="Management1",name="router-1.example.com",role="spine",tenant="customer1"} 1e+09
```

#### special: metadata

```yaml
commands:
  show ip bgp summary:
    type: multiple
    lookup_keys: ['vrfs', 'peers']
    metrics:
      - name: prefixReceived
    labels:
      - name: version
      - name: asn
      - name: peers
        prom_name: peer
        special: metadata
      - name: vrfs
        prom_name: vrf
        special: metadata
```

A special label of kind `metadata` can be used, in conjunction with a `multiple` metric, to expose information gathered when descending into the nested dictionaries.
The label's `name` must be a lookup key, and since the eAPI uses the plural form, a `prom_name` is often useful for the label to have meaning.

Given the JSON example [shown above](#multiple-1), the metrics would look like this :

```
arista_show_ip_bgp_summary_prefixReceived{asn="1234",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.2",role="spine",tenant="customer1",version="4",vrf="default"} 0.0
arista_show_ip_bgp_summary_prefixReceived{asn="1234",hostname="198.51.100.1",name="router-1.example.com",peer="192.168.1.1",role="spine",tenant="customer1",version="4",vrf="default"} 0.0
```

### API reachability metric

This exporter also generate one metric, `arista_api_unreachable`, which is a counter of each time an HTTPS query was unsuccessful (regardless of the reason) on the target.

## Using docker

### Building an image

You can build and run a docker image of this exporter using the provided dockerfile. It will embed the `api_commands.yaml` present in the repository. You may also create a `config.yaml` file at the root of the repository if you want to embed a config into the image. Alternatively, you can provide a configuration file with another mechanism (e.g. bind mount, Kubernetes configmap, etc.).

### Using automatically built images

Images available on the Docker Hub (`enix/arista-eapi-exporter`) and on Github Container Registry (`ghcr.io/enix/arista-eapi-exporter`) are automatically built on each tagged version of this repository. They use the provided `api_commands.yaml` but do not embed any configuration.

On these two image repositories, `latest` is the latest tag, there is no automatic nightly build.

To run it, you can use the provided `docker-compose.yaml` file, which mounts a `config.yaml` it expects to find alongside itself.

To start the latest version of the exporter in the background and immediately start displaying its log output :
```
docker compose pull
docker compose up -d && docker compose logs -f
```

To stop it :
```
docker compose down
```

Currently, the exporter cannot be configured using environment variables.


