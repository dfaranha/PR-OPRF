#ifndef LIBOT_PRE_H
#define LIBOT_PRE_H

#include "coproto/Socket/AsioSocket.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h"
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include <vector>
#include <array>
#include <span>

#ifdef ENABLE_MALICIOUS
    using OTExtTypeSender = osuCrypto::SoftSpokenMalOtSender;
    using OTExtTypeReceiver = osuCrypto::SoftSpokenMalOtReceiver;
#else
    using OTExtTypeSender = osuCrypto::SoftSpokenShOtSender<>;
    using OTExtTypeReceiver = osuCrypto::SoftSpokenShOtReceiver<>;
#endif

#ifdef ENABLE_PQ
    using BaseOTType = osuCrypto::MasnyRindalKyber;
#else
    using BaseOTType = osuCrypto::MasnyRindal;
#endif

namespace libotpre{

// bool is_malicious = false;
// bool is_pq = false;

// void set_malicious() { 
//     is_malicious = true; 
// }

// void set_pq() {
//     is_pq = true;
// }

void preot_sender(size_t numOTs, std::span<std::array<osuCrypto::block, 2>> sMsgs, osuCrypto::Socket& sock) {

    OTExtTypeSender sender;
    BaseOTType bot;
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // setup base OTs
    osuCrypto::u64 baseOTs = sender.baseOtCount();
    std::vector<osuCrypto::block> rMsgBase(baseOTs);
    osuCrypto::BitVector choices(baseOTs);
    choices.randomize(prng);
    coproto::sync_wait(bot.receive(choices, rMsgBase, prng, sock));
    coproto::sync_wait(sock.flush());
    sender.setBaseOts(rMsgBase, choices);

    // OT extension
    coproto::sync_wait(sender.send(sMsgs, prng, sock));
    coproto::sync_wait(sock.flush());

}

void preot_receiver(size_t numOTs, osuCrypto::BitVector &choices, std::span<osuCrypto::block> rMsgs, osuCrypto::Socket& sock) {
    
    OTExtTypeReceiver receiver;
    BaseOTType bot;
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // setup base OTs
    osuCrypto::u64 baseOTs = receiver.baseOtCount();
    std::vector<std::array<osuCrypto::block, 2>> sMsgBase(baseOTs);
    coproto::sync_wait(bot.send(sMsgBase, prng, sock));
    coproto::sync_wait(sock.flush());
    receiver.setBaseOts(sMsgBase);

    // OT extension
    choices.randomize(prng);
    coproto::sync_wait(receiver.receive(choices, rMsgs, prng, sock));
    coproto::sync_wait(sock.flush());    

}
};

using namespace emp;

template<typename IO>
class LibOTPre { public:
	IO* io;
	block * pre_data = nullptr;
	bool * bits = nullptr;
	int n;
	vector<block*> pointers;
	vector<const bool*> choices;
	vector<const block*> pointers0;
	vector<const block*> pointers1;

    OTExtTypeSender extsender;
    OTExtTypeReceiver extreceiver;
    osuCrypto::PRNG prng = osuCrypto::PRNG(osuCrypto::sysRandomSeed());

	CCRH ccrh;
	int length, count;
	block Delta;
	LibOTPre(IO* io, int length, int times) {
		this->io = io;
		this->length = length;
		n = length*times;
		pre_data = new block[2*n];
		bits = new bool[n];
		count = 0;
	}

	~LibOTPre() {
		if (pre_data != nullptr)
			delete[] pre_data;

		if (bits != nullptr)
			delete[] bits;
	}

    void send_gen_pre(osuCrypto::Socket &sock) {
        BaseOTType bot;
        osuCrypto::u64 numOTs = extsender.baseOtCount();
        std::vector<osuCrypto::block> recvMsg(numOTs);
        osuCrypto::BitVector choices(numOTs);
        choices.randomize(prng);

        coproto::sync_wait(bot.receive(choices, recvMsg, prng, sock));
        coproto::sync_wait(sock.flush());

        extsender.setBaseOts(recvMsg, choices);        
    }

    void recv_gen_pre(osuCrypto::Socket &sock) {
        BaseOTType bot;
        osuCrypto::u64 numOTs = extreceiver.baseOtCount();
        std::vector<std::array<osuCrypto::block, 2>> sendMsg(numOTs);

        coproto::sync_wait(bot.send(sendMsg, prng, sock));
        coproto::sync_wait(sock.flush());

        extreceiver.setBaseOts(sendMsg);        
    }

    void send_gen(osuCrypto::Socket &sock) {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> sMsgs(n);
        coproto::sync_wait(extsender.send(sMsgs, prng, sock));
        coproto::sync_wait(sock.flush());    
        for (int i = 0; i < n; i++) {
            memcpy(&pre_data[i], &sMsgs[i][0], sizeof(block));
            memcpy(&pre_data[i+n], &sMsgs[i][1], sizeof(block));
        }
    }

    void recv_gen(osuCrypto::Socket &sock) {
        osuCrypto::BitVector extchoices(n);
        extchoices.randomize(prng);
        osuCrypto::AlignedUnVector<osuCrypto::block> rMsgs(n);
        coproto::sync_wait(extreceiver.receive(extchoices, rMsgs, prng, sock));
        coproto::sync_wait(sock.flush());
        for (int i = 0; i < n; i++) {
            bits[i] = extchoices[i];
            memcpy(&pre_data[i], &rMsgs[i], sizeof(block));
        }
    }

	void send_pre(block * data, block in_Delta) {
		Delta = in_Delta;
		ccrh.Hn(pre_data, data, n, pre_data+n);
		xorBlocks_arr(pre_data+n, data, Delta, n);
		ccrh.Hn(pre_data+n, pre_data+n, n);
	}

	void recv_pre(block * data, bool * b) {
		memcpy(bits, b, n);
		ccrh.Hn(pre_data, data, n);
	}

	void recv_pre(block * data) {
		for(int i = 0; i < n; ++i)
			bits[i] = getLSB(data[i]);
		ccrh.Hn(pre_data, data, n);
	}

	void choices_sender() {
		count +=length;
	}

	void choices_recver(bool * b) {
		memcpy(b, bits+count, length);
		count +=length;
	}
	
	void reset() {
		count = 0;
	}

	void send(const block * m0, const  block * m1, int length, IO * io2, int s) {
		block pad[2];
		int k = s*length;
		for (int i = 0; i < length; ++i) {
				pad[0] = m0[i] ^ pre_data[k];
				pad[1] = m1[i] ^ pre_data[k+n];
			++k;
			io2->send_block(pad, 2);
		}
	}

	void recv(block* data, const bool* b, int length, IO* io2, int s) {
		int k = s*length;
		block pad[2];
		for (int i = 0; i < length; ++i) {
			io2->recv_block(pad, 2);
			int ind = b[i] ? 1 : 0;
			data[i] = pre_data[k] ^ pad[ind];
			++k;
		}
	}
};



#endif