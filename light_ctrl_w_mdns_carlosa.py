from coapthon.client.helperclient import HelperClient
import time
from zeroconf import Zeroconf

# Define the CoAP service name
coap_service_name = "light-ctrl-service._coap._udp.local."

def discover_server_address(service_name):
    try:
        print(f"searching for {coap_service_name}")
        zeroconf = Zeroconf()
        service_info = zeroconf.get_service_info("_coap._udp.local.", service_name)

        address_bytes = service_info.addresses[0]
        server_address = ".".join(str(byte) for byte in address_bytes)
        server_port = service_info.port
        print(f"server_address: {server_address}")
        print(f"server_port: {server_port}")
        return server_address, server_port
    except e:
        print(f"Error while trying to getting address of service: {service_name}")

    return 0,0

def coap_put_resource(resource_path, payload, server_address, server_port):
    try:
        client = HelperClient(server=(server_address, server_port))

        # Send a PUT request to the specified resource with the payload
        response = client.put(resource_path, payload)

        if response:
            print(f"Setting {resource_path}: {payload}")
            #print(f"Response: {response}")

        client.stop()
    except Exception as e:
        print(f"Error: {e}")
        
def coap_get_resource(resource_path, server_address, server_port):
    try:
        client = HelperClient(server=(server_address, server_port))

        # Send a GET request to the specified resource
        response = client.get(resource_path)

        if response:
            print(f"{resource_path}: {response.payload}")

        client.stop()
    except Exception as e:
        print(f"Error: {e}")
        
if __name__ == "__main__":
    # Discover the CoAP server address and port
    server_address, server_port = discover_server_address(coap_service_name)

    print(f"Discovered CoAP server: {server_address}:{server_port}")

    #read lights state
    coap_get_resource("light_state_0", server_address, server_port)
    coap_get_resource("light_state_1", server_address, server_port)
    
    #turning on lights
    coap_put_resource("light_command_0", "1", server_address, server_port)
    coap_put_resource("light_command_1", "1", server_address, server_port)
    
    #read lights state
    coap_get_resource("light_state_0", server_address, server_port)
    coap_get_resource("light_state_1", server_address, server_port)
    
    #turning all lights in "payload" time
    coap_put_resource("turn_off_timer", "10", server_address, server_port)
    
    #read lights state
    coap_get_resource("light_state_0", server_address, server_port)
    coap_get_resource("light_state_1", server_address, server_port)
    
    print("delay to read when lights are off")
    time.sleep(10)
    
    #read lights state
    coap_get_resource("light_state_0", server_address, server_port)
    coap_get_resource("light_state_1", server_address, server_port)
        
    
    input()
