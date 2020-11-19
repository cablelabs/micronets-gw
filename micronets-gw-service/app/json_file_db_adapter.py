
import json, logging
from pathlib import Path

logger = logging.getLogger ('micronets-gw-service')

class JsonFileDBAdapter:
    def __init__(self, config):
        self.base_dir = config.get('JSONFILEDB_DIR_PATH')
        self.micronets_path = Path (self.base_dir, "micronets.json")
        self.devices_path = Path (self.base_dir, "micronets-devices.json")
        logger.info  (f"JsonFileDBAdapter: Instantiated JsonFileDBAdapter (using {self.base_dir}")

    def read_from_conf(self):
        # TODO: Add logic to check for incomplete writes and use staged files when incomplete
        if self.micronets_path.exists() and self.devices_path.exists():
            logger.info(f"JsonFileDBAdapter: Loading micronet DB from {self.micronets_path} and {self.devices_path}")
            with self.micronets_path.open('r') as infile:
                micronet_list = json.load(infile)
            with self.devices_path.open('r') as infile:
                device_lists = json.load(infile)
        else:
            logger.info(f"JsonFileDBAdapter: No JSON DB files found in {self.base_dir}")
            micronet_list = {}
            device_lists = {}
        return {'prefix' : [], 'micronets' : micronet_list, 'devices' : device_lists, 'postfix' : []}

    async def update(self, micronets, devices):
        logger.info(f"JsonFileDBAdapter: Saving micronet definitions to {self.micronets_path}")
        # TODO: Write these to stage files and relink (to avoid partially written configs)
        with self.micronets_path.open ('w') as outfile:
            json.dump (micronets, outfile, indent=4)
        logger.info(f"JsonFileDBAdapter: Saving device definitions to {self.devices_path}")
        with self.devices_path.open ('w') as outfile:
            json.dump (devices, outfile, indent=4)

if __name__ == '__main__':
    print ("Running JSON file DB parse/generation test cases")
    logger = logging.getLogger('testing')
    myconfig = {'JSONFILEDB_DIR_PATH':  "./lib"}
    db_adapter = JsonFileDBAdapter(myconfig)
    conf_file_elems = db_adapter.read_from_conf()
    print("Done parsing.")
    print("Found micronets:")
    print(json.dumps (conf_file_elems ['micronets'], indent=2))
    print("Found devices:")
    print(json.dumps (conf_file_elems ['devices'], indent=2))
