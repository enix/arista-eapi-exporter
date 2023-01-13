#!/usr/bin/env python
# coding: utf-8
from argparse import ArgumentParser
import sys
import logging
from signal import signal, SIGTERM
import copy

from time import sleep, time
import requests
import requests_unixsocket
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import yaml
from prometheus_client import start_http_server
from prometheus_client import Counter, Gauge, Enum


PROM_PREFIX = "arista_"  # Every metric name will be prefixed with this

REQUEST_BODY = {
    "jsonrpc": "2.0",
    "method": "runCmds",
    "id": 1,
    "params": {
        "version": 1,
        "cmds": None,
    },
}


logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger(__name__)


def terminate(*_):  # pylint: disable=missing-function-docstring
    logger.info("Received SIGTERM, exiting.")
    sys.exit(0)


def get_metric_prom_name(command, metric_path):
    "From the API command, and the metric path inside the API response, return a suitable name for Prometheus"
    return PROM_PREFIX + command.replace(" ", "_") + "_" + metric_path.replace(".", "_")


def flatten_eapi_response(lookup_keys, result, flattened_result, metadata=None):
    """
    Recursively update a list, `flattened_result` by going through the nested dict `result` via each level specified
    in `lookup key`.
    At each level, loop through all items (such as VRFs or interfaces), and register their identifiers in `metadata`.

    Here is an example of what this function would have to process :

    lookup_keys = ['vrfs', 'peers']

    result = {'vrfs':
                {'default':
                    {'peers':
                        {'192.168.1.1': {'prefixReceived': 10,
                                         'msgSent': 1,
                                         'asn': 1234},
                         '192.168.1.2': {'prefixReceived': 20,
                                         'msgSent': 2,
                                         'asn': 1234}},
                    }
                }
             }

    The content of `flattened_result` after calling this function would be :

    [
        {'metadata': {'vrfs': 'default', 'peers': '192.168.1.1'},
        'data': {'prefixReceived': 10, 'msgSent': 1, 'asn': 1234}},

        {'metadata': {'vrfs': 'default', 'peers': '192.168.1.2'},
        'data': {'prefixReceived': 20, 'msgSent': 2, 'asn': 1234}}
    ]

    """

    if metadata is None:  # Root call, initialize metadata
        metadata = {}

    # Loop through each of the item of the current depth level
    for item_name, item_value in result[lookup_keys[0]].items():

        # Extract this level's metadata (vrf name, peer IP, etc.)
        metadata[lookup_keys[0]] = item_name

        if len(lookup_keys) != 1:
            # We are not at the last lookup key, go one level deeper
            flatten_eapi_response(
                lookup_keys[1:], item_value, flattened_result, copy.deepcopy(metadata)
            )

        else:
            # We are at the last lookup key, here is the interesting data
            flattened_result.append(
                {"metadata": copy.deepcopy(metadata), "data": item_value}
            )


def main():  # pylint: disable=missing-function-docstring
    signal(SIGTERM, terminate)

    parser = ArgumentParser(
        description="Launch a Prometheus Exporter exposing metrics from Arista EOS devices via their eAPI."
    )

    parser.add_argument(
        "-a",
        "--api-commands",
        default="/etc/arista-eapi-exporter/api_commands.yaml",
        help="YAML config file containing API commands to execute and what metrics to export",
    )

    parser.add_argument(
        "-d",
        "--debug",
        help="Display debugging statements",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.INFO,
    )

    subparsers = parser.add_subparsers(dest="kind")
    subparsers.required = True

    parser_multiple = subparsers.add_parser("multiple")
    # parser_multiple.set_defaults(kind="multiple")
    parser_multiple.add_argument(
        "-c",
        "--config",
        default="/etc/arista-eapi-exporter/config.yaml",
        help="YAML config file containing targets and credentials",
    )

    parser_single = subparsers.add_parser("single")
    # parser_single.set_defaults(kind="single")
    parser_single.add_argument(
        "-s",
        "--socket",
        required=True,
        choices=["unix", "ip"],
        default="unix",
        help="Wether to use UNIX or IP socket",
    )
    parser_single.add_argument(
        "-t",
        "--target",
        default=None,
        help="Target URL. Defaults to 'https://172.17.0.1/command-api' or 'http+unix://%%2Fvar%%2Frun%%2Fcommand-api.sock/command-api' depending on the socket type.",
    )
    parser_single.add_argument(
        "-u",
        "--username",
        help="Username to use when connecting using an IP socket. EOS ignores credentials when using an UNIX socket.",
    )
    parser_single.add_argument(
        "-p",
        "--password",
        help="Password to use when connecting using an IP socket. EOS ignores credentials when using an UNIX socket.",
    )
    parser_single.add_argument(
        "-k",
        "--allow-insecure",
        action="store_true",
        help="Do not perform a strict check of HTTPS certificate when using IP socket with an HTTPS URL.",
    )
    parser_single.add_argument(
        "-w",
        "--timeout",
        default=5,
        help="Seconds to wait when performing HTTP requests to the API. Defaults to 5.",
    )
    parser_single.add_argument(
        "-i",
        "--interval",
        default=300,
        help="Interval, in seconds, to use for refreshing all metrics on all targets. Defaults to 300 (5 minutes).",
    )
    parser_single.add_argument(
        "--listen-port",
        default=9100,
        help="HTTP port where the exporter will bind. Defaults to 9100.",
    )
    parser_single.add_argument(
        "-l",
        "--label",
        default=[],
        action="append",
        nargs=2,
        metavar=("NAME", "VALUE"),
        help="Additionnal label to export at host level (i.e. on all metrics). Can be repeated.",
    )

    args = parser.parse_args()

    logger.setLevel(args.loglevel)

    # Custom default for target, when in single mode
    if args.kind == "single" and args.target is None:
        if args.socket == "unix":
            args.target = "http+unix://%2Fvar%2Frun%2Fcommand-api.sock/command-api"
        elif args.socket == "ip":
            args.target = "https://172.17.0.1/command-api"

    # Disable unverified certificate warning. If we request a self-signed API, that's on purpose
    disable_warnings(InsecureRequestWarning)

    # Global parameters and file loading
    if args.kind == "multiple":
        logging.info("Loading config file at %s", args.config)
        with open(args.config, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
        if config is None:
            raise ValueError(f"Config file {args.config} is empty")
        interval = int(config["global"]["interval"])
        prom_port = int(config["global"]["listen_port"])
    elif args.kind == "single":
        interval = int(args.interval)
        prom_port = int(args.listen_port)

    logging.info("Loading API commands file at %s", args.api_commands)
    with open(args.api_commands, "r", encoding="utf-8") as file:
        api_commands = yaml.safe_load(file)
    if api_commands is None:
        raise ValueError(f"API api_commands file {args.api_commands} is empty")

    if args.kind == "single" and args.socket == "unix":
        requests_unixsocket.monkeypatch()

    # This will hold all targets, along with their connection parameters and prom labels
    targets = []
    # This will be replaced with a list of the host-level labels' names (i.e. labels present on every metric)
    host_labels = []

    # Build target list. The method depends heavily on the mode of operation (multiple or single)

    # If we are in multiple mode, get all info from the config file. Fill defaults value if needed.
    if args.kind == "multiple":
        custom_host_labels = config["global"]["custom_host_labels"]
        host_labels = ["hostname", "name"] + custom_host_labels

        # These are the metadata (i.e. connection parameters, host labels, etc.) that can either be defined (in the config)
        # in the defaults, or in each target
        defaultable_parameters = [
            "username",
            "password",
            "port",
            "allow_insecure",
            "timeout",
        ] + custom_host_labels

        for target_config in config["targets"]:
            target = {}

            # name
            target_name = target_config["name"]
            logger.info("Building parameters and metadata for %s", target_name)
            target["name"] = target_name

            # Rest of the connection params and custom host labels
            try:
                for parameter in defaultable_parameters:
                    if (value := target_config.get(parameter)) is None:
                        value = config["defaults"][parameter]
                        logger.debug(
                            "%s : setting %s from defaults", target_name, parameter
                        )
                    target[parameter] = value
            except KeyError as exc:
                _, exc_value, _ = sys.exc_info()
                raise ValueError(
                    f"You need to set the config attribute {exc_value}, on the target {target_name} or in the defaults"
                ) from exc

            # hostname and url
            hostname = target_config.get("hostname", target_name)
            target["hostname"] = hostname
            target["url"] = f"https://{hostname}:{target['port']}/command-api"

            # We're all good
            targets.append(target)

    # If we are in single mode, the target list will contain only one item, and most of the connection params and labels
    # will come from the command line arguments. Except the host name, which will be retrieved dynamically after.
    elif args.kind == "single":
        custom_host_labels = [
            name for name, _value in args.label
        ]  # For now we only care for label names.
        host_labels = ["name"] + custom_host_labels

        # Global params

        target = {}

        # username
        target["username"] = args.username

        # password
        target["password"] = args.password

        # allow_insecure
        target["allow_insecure"] = args.allow_insecure

        # timeout
        target["timeout"] = args.timeout

        # url
        target["url"] = args.target

        # name, will be retrieved later, using the API directly from the target.
        # It is better to do that in the infinite polling loop because then we get auto retry
        # and can increase the "api unreachable" metric in case of failure
        target["name"] = None

        # custom host labels
        for label_name, label_value in args.label:
            # Avoid overwriting a connection parameter (url, username, etc.)
            if label_name in target:
                raise ValueError(
                    "{label_name} is not an authorized label as it conflicts with a parameter."
                )
            target[label_name] = label_value

        # We're all good
        targets = [target]

    exported_metrics = {}  # The prometheus gauges and counters will be stored here

    # Initialize prometheus metrics

    for command, command_details in api_commands["commands"].items():
        # Normalize labels, i.e. translate the ones that need to be translated (because of a conflict for instance).
        # Those are the one with an attribute "prom_name" instead of just a "name"
        normalized_labels = [
            label.get("prom_name", label["name"])
            for label in command_details.get("labels", [])
        ]

        # Create all metrics under the current API command
        for metric in command_details["metrics"]:
            metric_name = get_metric_prom_name(command, metric["name"])
            metric_type = metric.get("type", "gauge")  # Default metric type is a Gauge

            if metric_type == "gauge" or metric_type == "mapping":
                exported_metrics[metric_name] = Gauge(
                    metric_name,
                    f"Arista EOS metric '{metric['name']}' under '{command}'",
                    labelnames=host_labels + normalized_labels,
                )
            elif metric_type == "enum":
                exported_metrics[metric_name] = Enum(
                    metric_name,
                    f"Arista EOS metric '{metric['name']}' under '{command}'",
                    labelnames=host_labels + normalized_labels,
                    states=metric["enum"],
                )

    # This will hold each set of label:value ("labelset") PREVIOUSLY KNOWN for each metric. At each poll cycle, it will be compared
    # with the retrieved label:value set, in order to remove the no-longer-valid ones.
    # The goal is to clear metrics for removed FW rules, interfaces, VLANs etc. which are represented as labels.
    # For now, initialize it with the metrics names. It is done before the initialization of "api_unreachable" by design
    # so that that particular metric is never cleared.
    labelsets_known = {key: [] for key in exported_metrics}

    # Init one more metric to check for API reachability
    exported_metrics[PROM_PREFIX + "api_unreachable"] = Counter(
        PROM_PREFIX + "api_unreachable", "Number of failed API requests", host_labels
    )
    # Do a first sweep on all targets to set `api_unreachable` to 0
    for target in targets:
        # Extract host-level labels with their values
        target_labels = {}
        for label in host_labels:
            target_labels[label] = target[label]
        exported_metrics[PROM_PREFIX + "api_unreachable"].labels(**target_labels).inc(0)

    # Let's roll baby !
    logger.info("Starting the HTTP server on port %s", prom_port)
    start_http_server(prom_port)

    # Fetch metrics from routers
    command_list = list(api_commands["commands"].keys())
    while True:

        start_time = time()

        # Same as labelsets_known but will contain only labelsets retrived during this poll cycle
        labelsets_current = {key: [] for key in exported_metrics}

        for target in targets:

            # Extract host-level labels with their values
            target_labels = {}
            for label in host_labels:
                target_labels[label] = target[label]

            # Prepare the request parameters
            auth = (target["username"], target["password"])
            verify = not target["allow_insecure"]

            # If the name is not defined, dynamically try to get it
            if target["name"] is None:
                logger.info("Getting hostname of target '%s'", target["url"])

                hostname_body = copy.deepcopy(REQUEST_BODY)
                hostname_body["params"]["cmds"] = ["show hostname"]
                try:
                    resp = requests.post(
                        target["url"],
                        auth=auth,
                        verify=verify,
                        json=hostname_body,
                    )
                    resp.raise_for_status()
                except Exception as exc:  # pylint: disable=broad-except
                    logger.error("%s: %s", type(exc).__name__, exc)
                    logger.error(
                        "Error while requesting the name for %s, skipping this target.",
                        target["url"],
                    )
                    exported_metrics[PROM_PREFIX + "api_unreachable"].labels(
                        **target_labels
                    ).inc()
                    break

                target_name = resp.json()["result"][0]["hostname"]
                target["name"] = target_name
                target_labels["name"] = target_name

            logger.info("Starting polling %s", target["name"])

            body = copy.deepcopy(REQUEST_BODY)
            # eAPI allows for all commands to be passed at the same time
            body["params"]["cmds"] = command_list

            try:
                resp = requests.post(
                    target["url"],
                    json=body,
                    auth=auth,
                    verify=verify,
                    timeout=target["timeout"],
                )
                resp.raise_for_status()
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("%s: %s", type(exc).__name__, exc)
                logger.error(
                    "Error while requesting %s, skipping this target.",
                    target["name"],
                )
                exported_metrics[PROM_PREFIX + "api_unreachable"].labels(
                    **target_labels
                ).inc()
                break
            responses = resp.json()["result"]

            # Break down the response list and correlate each one to its command/metric
            for index, command in enumerate(command_list):
                command_result = responses[index]
                command_definition = api_commands["commands"][command]

                try:
                    command_type = command_definition["type"]
                except KeyError as exc:
                    raise ValueError(
                        f"Command '{command}' should have a 'type' attribute"
                    ) from exc

                if command_type == "multiple":
                    # A command that returns data in multiple levels of nesting, for instance `show ip bgp summary`
                    # returns data per peer, per VRF
                    try:
                        lookup_keys = command_definition["lookup_keys"]
                    except KeyError as exc:
                        raise ValueError(
                            f"Command '{command}' of type 'multiple' should have a 'lookup_keys' attribute"
                        ) from exc

                    if isinstance(lookup_keys, str):
                        lookup_keys = [lookup_keys]

                    if not isinstance(lookup_keys, list):
                        raise ValueError(
                            f"'lookup_keys' for command '{command}' should be either a string or a list of strings. Got {repr(lookup_keys)} (type {type(lookup_keys)}) instead."
                        )

                    # Flatten the JSON output, i.e. all elements of the nested response in a single list, along with their
                    # metadata (vrf name and peer IP, in our example)
                    flattened_result = []
                    try:
                        flatten_eapi_response(
                            lookup_keys, command_result, flattened_result
                        )
                    except KeyError as exc:
                        _, exc_value, _ = sys.exc_info()
                        raise ValueError(
                            f"Returned data for command '{command}' on target '{target['name']}' did not contain a {exc_value} key. Please check API response or lookup keys '{lookup_keys}'."
                        )
                elif command_type == "flat":
                    # A command that returns data with exploitable values directly at the first level. E.g. `show version`
                    # Fake a one-item list with empty metadata for flat API response so that the rest of the processing is the same
                    flattened_result = [{"data": command_result, "metadata": {}}]
                else:
                    raise ValueError(
                        f"Unknown command type '{command_type}' for command '{command}'"
                    )

                # Look through all the items (interfaces, VLANs, etc) the API gave us
                for result in flattened_result:
                    data = result["data"]
                    metadata = result["metadata"]

                    # Extract metric-level label values such as interfaces names, comments, etc. depending on
                    # which API command we are passing.
                    extracted_labels = target_labels.copy()
                    for label in command_definition.get("labels", []):
                        # If we have a label name more suitable for prom, use it
                        label_prom_name = label.get("prom_name", label["name"])

                        special = label.get("special")  # Is this a "meta-label" ?
                        if special == "metadata":
                            # This label will contain metadata extracted when we flattened the eAPI response.
                            extracted_labels[label_prom_name] = metadata.get(
                                label["name"], ""
                            )
                        else:  # Just a normal non-meta plain old label
                            # If the label value is not present in the API response, default to ""
                            extracted_labels[label_prom_name] = data.get(
                                label["name"], ""
                            )

                    # Extract metrics and update the corresponding prom Gauge
                    for metric in command_definition["metrics"]:
                        metric_name = get_metric_prom_name(command, metric["name"])
                        # Default metric type is a Gauge
                        metric_type = metric.get("type", "gauge")

                        # Go as deep as we need into the JSON tree of the response
                        metric_path = metric["name"].split(".")
                        metric_data = data
                        try:
                            for step in metric_path:
                                metric_data = metric_data[step]
                        except KeyError:
                            logger.debug(
                                "Result for '%s' on target %s ('%s') do not contain an attribute named '%s'",
                                command,
                                target["name"],
                                metadata,
                                step,
                            )
                            continue  # If the item does not contain our desired metric, just skip it

                        # Magic happens here, update prometheus gauge or enum depending on the metric type :
                        if metric_type == "gauge":
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).set(metric_data)
                        elif metric_type == "enum":
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).state(metric_data)
                        elif metric_type == "mapping":
                            mapped_value = metric["mapping"].get(metric_data)
                            if mapped_value is None:
                                logger.error(
                                    "Unknown mapping for %s - %s from %s : got '%s' which is not in the mappings",
                                    command,
                                    metric["name"],
                                    target["name"],
                                    metric_data,
                                )
                                continue
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).set(mapped_value)

                        labelsets_current[metric_name].append(extracted_labels)

            logger.info("Finished polling %s", target["name"])

        # Compare labelsets retrieved during this cycle to labelsets already known

        # First, check that each previously-known labelset is still valid. If not, clear it.
        for metric_name, labelsets in labelsets_known.items():
            for known_labelset in labelsets:
                if known_labelset not in labelsets_current[metric_name]:
                    logger.info(
                        "Removing labelset %s for metric %s",
                        known_labelset,
                        metric_name,
                    )
                    # So long, Bowser !
                    exported_metrics[metric_name].remove(*known_labelset.values())
                    labelsets_known[metric_name].remove(known_labelset)

        # Then, add the newly retrieved labelsets to the known ones for the next cycle
        for metric_name, labelsets in labelsets_current.items():
            for current_labelset in labelsets:
                if current_labelset not in labelsets_known[metric_name]:
                    labelsets_known[metric_name].append(current_labelset)

        end_time = time()
        elapsed_time = int(end_time - start_time)
        if (sleep_time := interval - elapsed_time) < 0:
            sleep_time = 0

        logger.info(
            "Polling finished for all devices. It took %s secs, so going to sleep for %s secs",
            elapsed_time,
            sleep_time,
        )
        sleep(sleep_time)


if __name__ == "__main__":
    main()
