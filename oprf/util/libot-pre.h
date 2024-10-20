#ifndef LIBOT_PRE_H
#define LIBOT_PRE_H

#include "coproto/Socket/AsioSocket.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h"
#include <vector>
#include <array>
#include <span>

namespace libotpre{

bool is_malicious = false;
bool is_pq = false;

void set_malicious() { 
    is_malicious = true; 
}

void set_pq() {
    is_pq = true;
}

void preot_sender(size_t numOTs, std::span<std::array<osuCrypto::block, 2>> sMsgs, osuCrypto::Socket& sock) {
    if (is_malicious == false && is_pq == false) {
        osuCrypto::SoftSpokenShOtSender<> sender;
        osuCrypto::MasnyRindal bot;
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
    } else if (is_malicious == true && is_pq == false) {
        osuCrypto::SoftSpokenMalOtSender sender;
        osuCrypto::MasnyRindal bot;
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
    // } else if (is_malicious == false && is_pq == true) {
    //     osuCrypto::SoftSpokenShOtSender<> sender;
    //     osuCrypto::MasnyRindalKyber bot;
    //     osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    //     // setup base OTs
    //     osuCrypto::u64 baseOTs = sender.baseOtCount();
    //     std::vector<osuCrypto::block> rMsgBase(baseOTs);
    //     osuCrypto::BitVector choices(baseOTs);
    //     choices.randomize(prng);
    //     coproto::sync_wait(bot.receive(choices, rMsgBase, prng, sock));
    //     coproto::sync_wait(sock.flush());
    //     sender.setBaseOts(rMsgBase, choices);

    //     // OT extension
    //     coproto::sync_wait(sender.send(sMsgs, prng, sock));
    //     coproto::sync_wait(sock.flush());        
    // } else {
    //     osuCrypto::SoftSpokenMalOtSender sender;
    //     osuCrypto::MasnyRindalKyber bot;
    //     osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    //     // setup base OTs
    //     osuCrypto::u64 baseOTs = sender.baseOtCount();
    //     std::vector<osuCrypto::block> rMsgBase(baseOTs);
    //     osuCrypto::BitVector choices(baseOTs);
    //     choices.randomize(prng);
    //     coproto::sync_wait(bot.receive(choices, rMsgBase, prng, sock));
    //     coproto::sync_wait(sock.flush());
    //     sender.setBaseOts(rMsgBase, choices);

    //     // OT extension
    //     coproto::sync_wait(sender.send(sMsgs, prng, sock));
    //     coproto::sync_wait(sock.flush());        
    // } 
}

void preot_receiver(size_t numOTs, osuCrypto::BitVector &choices, std::span<osuCrypto::block> rMsgs, osuCrypto::Socket& sock) {
    if (is_malicious == false && is_pq == false) {
        osuCrypto::SoftSpokenShOtReceiver<> receiver;
        osuCrypto::MasnyRindal bot;
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
    } else if (is_malicious == true && is_pq == false) {
        osuCrypto::SoftSpokenMalOtReceiver receiver;
        osuCrypto::MasnyRindal bot;
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
    // } else if (is_malicious == false && is_pq == true) {
    //     osuCrypto::SoftSpokenShOtReceiver<> receiver;
    //     osuCrypto::MasnyRindalKyber bot;
    //     osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    //     // setup base OTs
    //     osuCrypto::u64 baseOTs = receiver.baseOtCount();
    //     std::vector<std::array<osuCrypto::block, 2>> sMsgBase(baseOTs);
    //     coproto::sync_wait(bot.send(sMsgBase, prng, sock));
    //     coproto::sync_wait(sock.flush());
    //     receiver.setBaseOts(sMsgBase);

    //     // OT extension
    //     choices.randomize(prng);
    //     coproto::sync_wait(receiver.receive(choices, rMsgs, prng, sock));
    //     coproto::sync_wait(sock.flush());     
    // } else {
    //     osuCrypto::SoftSpokenMalOtReceiver receiver;
    //     osuCrypto::MasnyRindalKyber bot;
    //     osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    //     // setup base OTs
    //     osuCrypto::u64 baseOTs = receiver.baseOtCount();
    //     std::vector<std::array<osuCrypto::block, 2>> sMsgBase(baseOTs);
    //     coproto::sync_wait(bot.send(sMsgBase, prng, sock));
    //     coproto::sync_wait(sock.flush());
    //     receiver.setBaseOts(sMsgBase);

    //     // OT extension
    //     choices.randomize(prng);
    //     coproto::sync_wait(receiver.receive(choices, rMsgs, prng, sock));
    //     coproto::sync_wait(sock.flush());     
    // }
}

};




#endif