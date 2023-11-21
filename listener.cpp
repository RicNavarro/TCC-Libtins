#include <tins/tins.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <set>

using namespace std;
using namespace Tins;

class GeneralSniffer{
	public:
		void run(const string& iface);
	private:
		typedef Dot11::address_type tipo_endereco;
		typedef 
		typedef set<tipo_endereco> tipo_ssids;
		
		bool callback(PDU& pdu);
		
		//tipo_ssids ssids;
};

void GeneralSniffer::run(const string& iface){
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_rfmon(true);
	config.set_filter("type mgt");
	Sniffer sniffer(iface, config);
	sniffer.sniff_loop(make_sniffer_handler(this, &GeneralSniffer::callback));
}

bool GeneralSniffer::callback(PDU& pdu){
	// Conseguindo a camada Dot11
	const Dot11ManagementFrame& dotonze = pdu.rfind_pdu<Dot11ManagementFrame>();
	
	tipo_endereco addr = dotonze.addr2();

	//---tipo_ssids::iterator iter = ssids.find(addr);
	
	//---if (iter == ssids.end()){
		//primeira vez encontrando esse bssid
		try{
			//Se nenhuma opção de ssid está pronta, então uma exceção std::runtime_error é lançada por Dot11ManagementFrame:ssid
			string ssid = dotonze.ssid();
			string addr_string = addr.to_string();
			
			// salvando na lista de ssids
			//---ssids.insert(addr);
			
			//Exibir a tupla "address - ssid"
			cout << dotonze.pdu_type().to_string() << "MAC: " << addr << endl << "SSID: " << ssid << endl;
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
	GeneralSniffer sniffer;
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
