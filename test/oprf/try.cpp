#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include "oprf/oprf.h"

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/CLP.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"
#include "cryptoTools/Network/util.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h"


#include "oprf/util/libot-pre.h"


#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

int main(int argc, char **argv) {
  mpz_class num("500");
  std::vector<uint8_t> x(48);
  mpz_export(&x[0], NULL, -1, 1, 0, 0, num.get_mpz_t());
  cout << (int)x[0] << ' ' << (int)x[1] << ' ' << (int)x[2] << ' ' << (int)x[3] << endl;
  cout << num << endl;
  mpz_class num2;
  mpz_import(num2.get_mpz_t(), 48, -1, 1, 0, 0, &x[0]);
  cout << num2 << endl;

  int party = std::atoi(argv[1]);

  //libotpre::set_malicious();

  if (party == 1) {

    auto sock = osuCrypto::cp::asioConnect("127.0.0.1:12345", true); 
    // osuCrypto::SoftSpokenShOtReceiver extreceiver;
    // osuCrypto::SimplestOT xxx;
    // osuCrypto::SoftSpokenMalOtReceiver extreceiver;
    // osuCrypto::MasnyRindal xxx;
    
    //osuCrypto::setThreadName("Sender");
    // osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // osuCrypto::u64 numOTs = extreceiver.baseOtCount();
    // std::vector<std::array<osuCrypto::block, 2>> sendMsg(numOTs);

    // auto p0 = xxx.send(sendMsg, prng, sock);
    // coproto::sync_wait(p0);
    // coproto::sync_wait(sock.flush());

    // extreceiver.setBaseOts(sendMsg);
    // std::cout << "comm: " << sock.bytesReceived()+sock.bytesSent() << std::endl;

    int extotnum = 384;
    osuCrypto::BitVector extchoices(extotnum);
    // extchoices.randomize(prng);
    osuCrypto::AlignedUnVector<osuCrypto::block> rMsgs(extotnum);
    // coproto::sync_wait(extreceiver.receive(extchoices, rMsgs, prng, sock));
    // coproto::sync_wait(sock.flush());

    libotpre::preot_receiver(extotnum, extchoices, rMsgs, sock);

    for (int i = 0; i < 10; i++) {      
      std::cout << i << ':' << std::endl;
      std::cout << extchoices[i] << ' ' << rMsgs[i] << std::endl;
    }    

    std::cout << "comm: " << sock.bytesReceived()+sock.bytesSent() << std::endl;

  } else {

    auto sock = osuCrypto::cp::asioConnect("127.0.0.1:12345", false);
    // osuCrypto::SoftSpokenShOtSender extsender;
    // osuCrypto::SimplestOT xxx;
    //osuCrypto::SoftSpokenMalOtSender extsender;
    //osuCrypto::MasnyRindal xxx;
    

    //osuCrypto::setThreadName("Sender");
    // osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // osuCrypto::u64 numOTs = extsender.baseOtCount();
    // std::vector<osuCrypto::block> recvMsg(numOTs);
    // osuCrypto::BitVector choices(numOTs);
    // choices.randomize(prng);

    // auto p1 = xxx.receive(choices, recvMsg, prng, sock);
    // coproto::sync_wait(p1);
    // coproto::sync_wait(sock.flush());

    // extsender.setBaseOts(recvMsg, choices);
    // std::cout << "comm: " << sock.bytesReceived()+sock.bytesSent() << std::endl;

    int extotnum = 384;
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> sMsgs(extotnum);
    // coproto::sync_wait(extsender.send(sMsgs, prng, sock));
    // coproto::sync_wait(sock.flush());

    libotpre::preot_sender(extotnum, sMsgs, sock);


    for (int i = 0; i < 10; i++) {
      std::cout << i << ':' << std::endl;
      std::cout << sMsgs[i][0] << std::endl << sMsgs[i][1] << std::endl;
    }



    std::cout << "comm: " << sock.bytesReceived()+sock.bytesSent() << std::endl;

  }


  return 0;
}
