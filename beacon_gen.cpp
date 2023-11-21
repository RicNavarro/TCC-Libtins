#include <tins/tins.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <set>

using namespace Tins;
using namespace std;

int main(int argc, char* argv[]){
	if (argc != 2){
		cout << "Usando <interface>: \"" <<* argv << "\"" << endl;
		return 1;
	}
	
	string interface = argv[1];
	cout << "Usando interface " << interface << endl;

	Dot11Beacon beacon;
	beacon.addr1(Dot11::BROADCAST);
	beacon.addr2("00:01:02:03:04:05");
	beacon.addr3(beacon.addr2());
	
	beacon.ssid("libtins");
	beacon.supported_rates({1.0f, 5.5f, 11.0f});
	
	beacon.rsn_information(RSNInformation::wpa2_psk());
	
	RadioTap radio = RadioTap() / beacon;
	PacketSender sender;
	
	int i = 0;
	while (i<100){
		sender.send(radio, interface);
		i++;
	}
}
