#pragma comment(lib,"cryptlib.lib")

#include <cryptopp/sha.h>
#include <iostream>
#include <fstream>
#include <cassert> 
#include <cryptopp/hex.h>
#include <math.h>
#include <iomanip>

using namespace std;
using namespace CryptoPP;

const string toHex(string str) {
	string hex;
	StringSource ss((const byte*)str.c_str(), str.size(), true,
		new HexEncoder(new StringSink(hex)));

	return hex;
}
int main() {
	std::string init = "109550027";
	std::string digest;

	ofstream out;
	out.open("out.txt");
	SHA256 hash;
	hash.Update((const byte*)init.data(), init.size());
	digest.resize(hash.DigestSize());
	hash.Final((byte*)&digest[0]);
	//cout << toHex(digest) << endl;
	for (int k = 0; k < 9; k++) {
		string prev = digest;
		string nonce, nonce0;
		Integer n = 0;
		for (int i = 0; i < pow(2, 32); i++) {


			stringstream ss, ss0;
			string nonce_arcii;
			ss << hex << n;
			ss >> nonce;
			nonce.erase(nonce.size() - 1);
			ss0 << setw(8) << setfill('0') << nonce;
			ss0 >> nonce0;
			//cout << nonce0 << endl;
			StringSource ss2(nonce0, true, new HexDecoder(new StringSink(nonce_arcii)));
			string msg = prev + nonce_arcii;
			hash.Update((const byte*)msg.data(), msg.size());
			digest.resize(hash.DigestSize());
			hash.Final((byte*)&digest[0]);
			string digesth = toHex(digest);
			if (k == 0) {
				out << 0 << endl << toHex(prev) << endl << nonce0 << endl << digesth << endl;
				break;
			}
			int leadzero = 1;
			for (int j = 0; j < k; j++) {
				if (digesth.c_str()[j] != '0') {
					leadzero = 0;
					break;
				}
			}
			if (leadzero == 1) {
				out << k << endl << toHex(prev) << endl << nonce0 << endl << digesth << endl;
				break;
			}
			n++;
		}
		//cout << k << endl;
	}




}

