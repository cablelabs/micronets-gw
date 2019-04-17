from pathlib import Path
import json

class MockAdapter:
    def __init__ (self, base_dir="./"):
        self.base_dir = base_dir
        self.mock_micronets_path = Path (base_dir, "mock_micronets.json")
        self.mock_devices_path = Path (base_dir, "mock_devices.json")
        print ("Instantiated MockAdapter")

    def read_from_conf (self):
        if (self.mock_micronets_path.exists () and self.mock_devices_path.exists ()):
            print ("MockAdapter: Loading mock micronet data from {} and {}"
                   .format (self.mock_micronets_path, self.mock_devices_path))
            with self.mock_micronets_path.open ('r') as infile:
                micronet_list = json.load (infile)
            with self.mock_devices_path.open ('r') as infile:
                device_lists = json.load (infile)
        else:
            print ("MockAdapter: Initializing mock micronet/device lists")
            micronet_list = {}
            device_lists = {}
        return {'prefix' : [], 'micronets' : micronet_list, 'devices' : device_lists, 'postfix' : []}

    def save_to_conf (self, micronets, devices):
        print ("MockAdapter: Saving micronet data to {} and {}"
               .format (self.mock_micronets_path, self.mock_devices_path))
        with self.mock_micronets_path.open ('w') as outfile:
            json.dump (micronets, outfile)
        with self.mock_devices_path.open ('w') as outfile:
            json.dump (devices, outfile)

if __name__ == '__main__':
    print ("Running DHCP mock conf parse/generation test cases")
    dhcp_mock_adapter = MockAdapter ()
    conf_file_elems = dhcp_mock_adapter.read_from_conffile ()
    print ("Done parsing.")
    print ("Found micronets:")
    print (json.dumps (conf_file_elems ['micronets'], indent=2))
    print ("Found devices:")
    print (json.dumps (conf_file_elems ['devices'], indent=2))
