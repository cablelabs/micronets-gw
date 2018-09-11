from pathlib import Path
import json

class MockAdapter:
    def __init__ (self, base_dir="./"):
        self.base_dir = base_dir
        self.subnet_file_path = Path (base_dir, "dhcp_subnet_entries.json")
        self.device_file_path = Path (base_dir, "dhcp_device_entries.json")
        print ("Instantiated MockAdapter")

    def read_from_conf (self):
        if (self.subnet_file_path.exists () and self.device_file_path.exists ()):
            print ("MockAdapter: Loading mock subnet data from {} and {}"
                   .format (self.subnet_file_path, self.device_file_path))
            with self.subnet_file_path.open ('r') as infile:
                subnet_list = json.load (infile)
            with self.device_file_path.open ('r') as infile:
                device_lists = json.load (infile)
        else:
            print ("MockAdapter: Initializing mock subnet/device lists")
            subnet_list = {}
            device_lists = {}
        return {'prefix' : [], 'subnets' : subnet_list, 'devices' : device_lists, 'postfix' : []}

    def save_to_conf (self, subnets, devices):
        print ("MockAdapter: Saving subnet data to {} and {}"
               .format (self.subnet_file_path, self.device_file_path))
        with self.subnet_file_path.open ('w') as outfile:
            json.dump (subnets, outfile)
        with self.device_file_path.open ('w') as outfile:
            json.dump (devices, outfile)

if __name__ == '__main__':
    print ("Running DHCP mock conf parse/generation test cases")
    dhcp_mock_adapter = MockAdapter ()
    conf_file_elems = dhcp_mock_adapter.read_from_conffile ()
    print ("Done parsing.")
    print ("Found subnets:")
    print (json.dumps (conf_file_elems ['subnets'], indent=2))
    print ("Found devices:")
    print (json.dumps (conf_file_elems ['devices'], indent=2))
