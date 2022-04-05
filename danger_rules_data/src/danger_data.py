from cProfile import label
import os
import yaml
import time
import urllib.request
import certifi
import ssl
import csv

from datetime import datetime
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    SimpleObservable,
    OpenCTIStix2Utils   
)

from stix2 import(
    Bundle,
    ExternalReference,
    TLP_WHITE
)

class Datadanger():
    def __init__(self):
        config_file_path = "{}/config.yml".format(
            os.path.dirname(os.path.abspath(__file__))
        )
        config = (
            yaml.load(open(config_file_path), Loader = yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else{}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.datadanger_url = get_config_variable(
            "DATADANGER_URL", ["datadanger", "url"], config
        )
        self.datadanger_interval = get_config_variable(
            "DATADANGER_INTERVAL", ["datadanger", "interval"], config
        )
        self.create_indicators = get_config_variable(
            "VXVAULT_CREATE_INDICATORS",
            ["vxvault", "create_indicators"],
            config,
            False,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        # self.identity = self.helper.api.identity.create(
        #     type="Organization",
        #     name="VX Vault",
        #     description="VX Vault is providing URLs of potential malicious payload.",
        # )

    def get_interval(self):
        return int(self.datadanger_interval) * 60 * 60 * 24
    
    def run(self):
        self.helper.log_info("Fetching datadanger dataset...")
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        +datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector have never run")
                if last_run is None or(
                    (timestamp-last_run)>((int(self.datadanger_interval) -1) * 60 *60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Datadanger run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        response = urllib.request.urlopen(
                            self.datadanger_url,
                            context = ssl.create_default_context(cafile=certifi.where()), 
                        )
                        csv_file_1 = response.read()
                        with open(
                            os.path.dirname(os.path.abspath(__file__)) + "/blist.csv", "wb",
                        ) as csvfile: 
                            # csvfile.write(csv_file_1)
                            writer = csv.writer(csvfile, quoting = csv.QUOTE_MINIMAL)     
                            writer.writerow(["IP", "Last Reported"])          
                            for x in range(csv_file_1):
                                writer.writerow(csv_file_1[x])                              
                        count = 0
                        bundle_object = []
                        with open(os.path.dirname(os.path.abspath(__file__)) + "/blist.csv") as csv_file:
                            csv_reader = csv.DictReader(csv_file)
                            for line in csv_reader:
                                count += 1
                                if count <=3:
                                    continue
                                external_reference = ExternalReference(
                                    source_name = "Danger IP",
                                    url = "https://danger.rulez.sk",
                                    description = "Danger IP"
                                )
                                stix_observable = SimpleObservable(
                                    id = OpenCTIStix2Utils.generate_random_stix_id(
                                        "x-opencti-simple-observable"
                                    ),
                                    key = "IPv4-Addr.value",
                                    value = line["# IP"],
                                    label = "DangerIP",
                                    description = line["Last Reported"],
                                    # object_making_refs = [TLP_WHITE],
                                    external_references = [external_reference]
                                )
                                bundle_object.append(stix_observable)
                        bundel = Bundle(
                            objects = bundle_object, allow_custom = True
                        ).serialize()
                        self.helper.send_stix2_bundle(
                            bundel,
                            update = self.update_existing_data,
                            work_id = work_id
                        )
                        if os.path.exists(
                            os.path.dirname(os.path.abspath(__file__)) + "/blist.txt"
                        ):
                            os.remove(
                                os.path.dirname(os.path.abspath(__file__)) + "/blist.txt"
                            )
                    except Exception as e:
                        self.helper.log_info(str(e))
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in:"
                        + str(round(self.get_interval() / 60 / 60 / 24 ,2))
                        + "days"
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)

if __name__ == "__main__":
    try:
        DatadangerConnector = Datadanger()
        DatadangerConnector.run()
    except Exception as e:
        print(e)
        time.sleep(60)
        exit(0)
