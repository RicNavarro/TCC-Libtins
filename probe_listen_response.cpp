#include <tins/tins.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <set>

using namespace std;
using namespace Tins;

class ProbeSniffer{
	public:
		void run(const string& iface);
	private:
		typedef Dot11::address_type tipo_endereco;
		typedef set<tipo_endereco> tipo_ssids;
		string interface_in_use;
		
		bool callback(PDU& pdu);
		
		//tipo_ssids ssids;
};

void ProbeSniffer::run(const string& iface){
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_rfmon(true);
	config.set_filter("subtype probe-req");
	Sniffer sniffer(iface, config);
	this->interface_in_use = iface;
	sniffer.sniff_loop(make_sniffer_handler(this, &ProbeSniffer::callback));
}

bool ProbeSniffer::callback(PDU& pdu){
	// Conseguindo a camada Dot11
	const Dot11ProbeRequest& dotonze = pdu.rfind_pdu<Dot11ProbeRequest>();
	//const Dot11AssocRequest& pior = pdu.rfind_pdu<Dot11AssocRequest>();
	Dot11ProbeResponse response;
	
	tipo_endereco addr1 = dotonze.addr1();
	tipo_endereco addr2 = dotonze.addr2();
	//---tipo_ssids::iterator iter = ssids.find(addr);
	
	//---if (iter == ssids.end()){
		//primeira vez encontrando esse bssid
		try{
			//Se nenhuma opção de ssid está pronta, então uma exceção std::runtime_error é lançada por Dot11ManagementFrame:ssid
					
			string ssid = dotonze.ssid();
			string addr_string = addr2.to_string();

			response.addr1(addr2);
			response.addr2("E8:20:E2:76:8E:AA");
			response.addr3(response.addr2());
			
			response.ssid(ssid);
			response.supported_rates({1.0f, 5.5f, 11.0f});
			
			response.rsn_information(RSNInformation::wpa2_psk());
			
			RadioTap radio = RadioTap() / response;
			PacketSender sender;
			sender.send(radio, this->interface_in_use);
			
			// salvando na lista de ssids
			//---ssids.insert(addr);
			
			//Exibir a tupla "address - ssid"
			cout << "------- Frame --------" << endl;
			cout << "MAC Destino: " << addr1 << endl;
			cout << "MAC Origem:  " << addr2 << endl;
			cout << "SSID: " << ssid << endl;
		
			cout << "---- Frame Gerado ----" << endl;
			cout << "MAC Destino: " << response.addr1() << endl;
			cout << "MAC Origem:  " << response.addr2() << endl;
			cout << "SSID: " << response.ssid() << endl;
			
		}
		
		catch (runtime_error&){
			cout << "Catch Runtime Error" << endl;
		}
	//---}
	return true;
}


int main(int argc, char* argv[]){
	if (argc != 2){
		cout << "Usando <interface>: \"" <<* argv << "\"" << endl;
		return 1;
	}
	
	string interface = argv[1];
	cout << "Usando interface " << interface << endl;
	ProbeSniffer sniffer;
	sniffer.run(interface);
}

/*
	
}

int main(){
	
	vector<Packet> vt;
	
	string interf_lis;
	
	
	SnifferConfiguration config;

	config.set_filter("port 80");
	config.set_rfmon(true)
	config.set_snap_len(400);
	
	cout << "Insira a interface a ser ouvida" << endl;
	cin >> interf_lis;
	Sniffer sniffer(interf_lis, config);
	
	while(vt.size() != 100){
		vt.push_back(sniffer.next_packet());
	}
	
	for(const auto& packet : vt){
		if(packet.pdu()->find_pdu<Dot11>()){
			const Dot11* dotonze = packet.pdu()->find_pdu<Dot11>();
			cout << "Addr: " << dotonze->addr1() << endl;
			cout << "Type: " << dotonze->pdu_type() << endl;
//			cout << "SSID: " << dotonze->options_type[0] << endl;

		}
		if(packet.pdu()->find_pdu<Dot11Beacon>()){
			const Dot11Beacon* dotbeacon = packet.pdu()->find_pdu<Dot11>();
			cout << "SSID: " << dotbeacon->ssid << endl;
		}
	}
	
	cout << "Hello world" << endl;
	return 0;
}
*/
