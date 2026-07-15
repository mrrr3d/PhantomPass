/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1997 The Regents of the University of California.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the Network Research
 * 	Group at Lawrence Berkeley National Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "connector.h"
#include "object.h"
#include "red.h"
#include "scheduler.h"
#include "tclcl.h"
#include <cstddef>
#include <cstdio>
#include <iomanip>
#include <cassert>
#include <cstdint>
#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /cvsroot/nsnam/ns-2/classifier/classifier-hash.cc,v 1.30 2005/09/18 23:33:31 tomh Exp $ (LBL)";
#endif

//
// a generalized classifier for mapping (src/dest/flowid) fields
// to a bucket.  "buckets_" worth of hash table entries are created
// at init time, and other entries in the same bucket are created when
// needed
//
//

extern "C" {
#include <tcl.h>
}

#include <stdlib.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include "simple-tracer.h"
#include "config.h"
#include "packet.h"
#include "ip.h"
#include "classifier.h"
#include "classifier-hash.h"
#include "r2p2-hdr.h"
#include "flags.h"
#include "net-interface.h"

/****************** HashClassifier Methods ************/

int HashClassifier::classify(Packet * p) {
	int slot= lookup(p);
	if (slot >= 0 && slot <=maxslot_)
		return (slot);
	else if (default_ >= 0)
		return (default_);
	return (unknown(p));
} // HashClassifier::classify

int HashClassifier::command(int argc, const char*const* argv)
{
	Tcl& tcl = Tcl::instance();
	/*
	 * $classifier set-hash $hashbucket src dst fid $slot
	 */

	if (argc == 7) {
		if (strcmp(argv[1], "set-hash") == 0) {
			//xxx: argv[2] is ignored for now
			nsaddr_t src = atoi(argv[3]);
			nsaddr_t dst = atoi(argv[4]);
			int fid = atoi(argv[5]);
			int slot = atoi(argv[6]);
			if (0 > set_hash(src, dst, fid, slot))
				return TCL_ERROR;
			return TCL_OK;
		}
	} else if (argc == 6) {
		/* $classifier lookup $hashbuck $src $dst $fid */
		if (strcmp(argv[1], "lookup") == 0) {
			nsaddr_t src = atoi(argv[3]);
			nsaddr_t dst = atoi(argv[4]);
			int fid = atoi(argv[5]);
			int slot= get_hash(src, dst, fid);
			if (slot>=0 && slot <=maxslot_) {
				tcl.resultf("%s", slot_[slot]->name());
				return (TCL_OK);
			}
			tcl.resultf("");
			return (TCL_OK);
		}
                // Added by Yun Wang to set rate for TBFlow or TSWFlow
                if (strcmp(argv[1], "set-flowrate") == 0) {
                        int fid = atoi(argv[2]);
                        nsaddr_t src = 0;  // only use fid
                        nsaddr_t dst = 0;  // to classify flows
                        int slot = get_hash( src, dst, fid );
                        if ( slot >= 0 && slot <= maxslot_ ) {
                                Flow* f = (Flow*)slot_[slot];
                                tcl.evalf("%u set target_rate_ %s",
                                        f, argv[3]);
                                tcl.evalf("%u set bucket_depth_ %s",
                                        f, argv[4]);
                                tcl.evalf("%u set tbucket_ %s",
                                        f, argv[5]);
                                return (TCL_OK);
                        }
                        else {
                          tcl.evalf("%s set-rate %u %u %u %u %s %s %s",
                          name(), src, dst, fid, slot, argv[3], argv[4],argv[5])
;
                          return (TCL_OK);
                        }
                }  
	} else if (argc == 5) {
		/* $classifier del-hash src dst fid */
		if (strcmp(argv[1], "del-hash") == 0) {
			nsaddr_t src = atoi(argv[2]);
			nsaddr_t dst = atoi(argv[3]);
			int fid = atoi(argv[4]);
			
			Tcl_HashEntry *ep= Tcl_FindHashEntry(&ht_, 
							     hashkey(src, dst,
								     fid)); 
			if (ep) {
				long slot = (long)Tcl_GetHashValue(ep);
				Tcl_DeleteHashEntry(ep);
				tcl.resultf("%lu", slot);
				return (TCL_OK);
			}
			return (TCL_ERROR);
		}
	}
	return (Classifier::command(argc, argv));
}

/**************  TCL linkage ****************/
static class SrcDestHashClassifierClass : public TclClass {
public:
	SrcDestHashClassifierClass() : TclClass("Classifier/Hash/SrcDest") {}
	TclObject* create(int, const char*const*) {
		return new SrcDestHashClassifier;
	}
} class_hash_srcdest_classifier;

static class FidHashClassifierClass : public TclClass {
public:
	FidHashClassifierClass() : TclClass("Classifier/Hash/Fid") {}
	TclObject* create(int, const char*const*) {
		return new FidHashClassifier;
	}
} class_hash_fid_classifier;

static class DestHashClassifierClass : public TclClass {
public:
	DestHashClassifierClass() : TclClass("Classifier/Hash/Dest") {}
	TclObject* create(int, const char*const*) {
		return new DestHashClassifier;
	}
} class_hash_dest_classifier;

static class SrcDestFidHashClassifierClass : public TclClass {
public:
	SrcDestFidHashClassifierClass() : TclClass("Classifier/Hash/SrcDestFid") {}
	TclObject* create(int, const char*const*) {
		return new SrcDestFidHashClassifier;
	}
} class_hash_srcdestfid_classifier;


// DestHashClassifier methods
int DestHashClassifier::classify(Packet *p)
{
	int slot= lookup(p);
    int ret_slot = slot;
	if (slot >= 0 && slot <= maxslot_)
		ret_slot = slot;
	else if (default_ >= 0)
		ret_slot = default_;
	else
		ret_slot = -1;

    /**
     * PPass logic
     */
    hdr_cmn* ch = hdr_cmn::access(p);
    if (enable_ppass_ && ch->ptype() == PT_UDP) {
        hdr_ip* ip_hdr = hdr_ip::access(p);
        int src = ip_hdr->src().addr_;
        int dst = ip_hdr->dst().addr_;
        hdr_r2p2* r2p2_hdr = hdr_r2p2::access(p);

        fprintf(stderr, "Dest classify: %d -> %d, msg_type=%d, size=%d\n", src, dst, r2p2_hdr->msg_type(), ch->size());
        // ingress
        int iface_in = ch->iface();
        ppass_ingress(iface_in, p);

        // egress
        NetworkInterface* out_iface = get_iface(ret_slot);
        if (out_iface != nullptr) {
            int iface_out = out_iface->intf_label();
            ppass_egress(iface_out, p);
        }
    }

    return ret_slot;
} // HashClassifier::classify

NetworkInterface* DestHashClassifier::get_iface(int slot) {
    if (slot < 0 || slot > maxslot_) {
        fprintf(stderr, "DestHashClassifier::get_iface: slot %d out of range\n", slot);
        return nullptr;
    }

    NsObject *obj = slot_[slot];
    if (obj == nullptr) {
        fprintf(stderr, "DestHashClassifier::get_iface: slot %d obj is nullptr\n", slot);
        return nullptr;
    }

    Connector *conn = dynamic_cast<Connector*>(obj);
    if (conn == nullptr || conn->target() == nullptr) {
        fprintf(stderr, "DestHashClassifier::get_iface: slot %d conn is nullptr or conn->target() is nullptr\n", slot);
        return nullptr;
    }

    Connector *sq = dynamic_cast<Connector*>(conn->target());
    if (sq == nullptr || sq->target() == nullptr) {
        fprintf(stderr, "DestHashClassifier::get_iface: slot %d sq is nullptr or sq->target() is nullptr\n", slot);
        return nullptr;
    }

    NetworkInterface *nif = dynamic_cast<NetworkInterface*>(sq->target());
    return nif;
} // DestHashClassifier::get_iface

void DestHashClassifier::ppass_ingress(int iface_label, Packet *p) {
    // fprintf(stderr, "ppass_ingress: id_=%d, iif=%d\n", id_, iface_label);

    PPassPortStatus &status = port_status_map_[iface_label];

    // ingress packet
    hdr_r2p2 *r2p2_hdr = hdr_r2p2::access(p);
    if (r2p2_hdr->msg_type() == hdr_r2p2::GRANT) {
        status.pqlen_ += r2p2_hdr->credit();
    }
    const uint64_t limit = static_cast<uint64_t>(pthr_) * 10;
    status.pqlen_ = std::min<uint64_t>(status.pqlen_, limit);

    status.pqlenInt_->newPoint(NOW, status.pqlen_);

} // DestHashClassifier::ppass_ingress

void DestHashClassifier::ppass_egress(int iface_label, Packet *p) {
    // fprintf(stderr, "ppass_egress: id_=%d, oif=%d\n", id_, iface_label);

    PPassPortStatus &status = port_status_map_[iface_label];

    hdr_cmn *ch = hdr_cmn::access(p);
    hdr_r2p2 *r2p2_hdr = hdr_r2p2::access(p);
    double now = Scheduler::instance().clock();

    if (r2p2_hdr->msg_type() == hdr_r2p2::GRANT || r2p2_hdr->unsol_credit() > 0 || r2p2_hdr->msg_type() == hdr_r2p2::GRANT_REQ) {
        status.pqlen_ += ch->size();
    }

    double interval = now - status.last_time_;
    if (status.last_time_ == 0.0) { // if last_time_ not used yet
        interval = 0;
    }
    status.last_time_ = now;

    uint64_t delta = static_cast<uint64_t>(rho_ * interval * line_rate_gbps_ * 125e6);
    status.pqlen_ = (delta > status.pqlen_) ? 0 : status.pqlen_ - delta;

    int egress_qlen = status.egress_queue_->byteLength();
    bool is_data_pkt = ((r2p2_hdr->msg_type() == hdr_r2p2::REQUEST || 
                         r2p2_hdr->msg_type() == hdr_r2p2::GRANT_REQ || 
                         r2p2_hdr->msg_type() == hdr_r2p2::REPLY));
    if (is_data_pkt && status.pqlen_ > pthr_ && egress_qlen > p_egress_queue_thresh_byte_) {
        hdr_flags::access(p)->ce() = 1;
    }
    const uint64_t limit = static_cast<uint64_t>(pthr_) * 10;
    status.pqlen_ = std::min<uint64_t>(status.pqlen_, limit);

    status.pqlenInt_->newPoint(now, status.pqlen_);

} // DestHashClassifier::ppass_egress

void SampleTimer::expire(Event *e)
{
    hash_classifier_->sample_qlen();
} // SampleTimer::expire

void DestHashClassifier::sample_qlen()
{
    if (!sample_header_written_) {
        if (sample_stream_.is_open()) {
            sample_stream_ << "Timestamp(s)";
            for (const auto& entry : port_status_map_) {
                int peer_id = entry.second.peer_id_;
                sample_stream_ << ",peer_" << peer_id << "_qlen(Byte)";
            }
            sample_stream_ << std::endl;
        } else {
            std::cerr << "DestHashClassifier::sample_qlen sample_stream_ not open\n";
            return;
        }
        sample_header_written_ = true;
    }

    // reference: ns2.34/ns-2.34/tcl/lib/ns-link.tcl: sample-queue-size

    double now = Scheduler::instance().clock();

    if (sample_stream_.is_open()) {
        sample_stream_ << std::fixed << std::setprecision(10) << now - 10;
    } else {
        std::cerr << "DestHashClassifier::sample_qlen sample_stream_ not open\n";
        return;
    }

    for (const auto& entry : port_status_map_) {
        const PPassPortStatus &status = entry.second;

        status.pqlenInt_->newPoint(now, status.pqlenInt_->getLasty());
        double bsum = status.pqlenInt_->getSum();
        double mean_qlen = bsum / sample_interval_;
        status.pqlenInt_->setSum(0.0);
        sample_stream_ << "," << mean_qlen;
    }
    sample_stream_ << std::endl;

    sample_timer_->resched(sample_interval_);
} // DestHashClassifier::sample_qlen

void DestHashClassifier::do_install(char* dst, NsObject *target) {
	nsaddr_t d = atoi(dst);
	int slot = getnxt(target);
	install(slot, target); 
	if (set_hash(0, d, 0, slot) < 0)
		fprintf(stderr, "DestHashClassifier::set_hash from within DestHashClassifier::do_install returned value < 0");
}

int DestHashClassifier::command(int argc, const char*const* argv)
{
	if (argc == 4) {
		// $classifier install $dst $node
		if (strcmp(argv[1], "install") == 0) {
			char dst[SMALL_LEN];
			strcpy(dst, argv[2]);
			NsObject *node = (NsObject*)TclObject::lookup(argv[3]);
			//nsaddr_t dst = atoi(argv[2]);
			do_install(dst, node); 
			return TCL_OK;
			//int slot = getnxt(node);
			//install(slot, node);
			//if (set_hash(0, dst, 0, slot) >= 0)
			//return TCL_OK;
			//else
			//return TCL_ERROR;
		} // if

        if (strcmp(argv[1], "set-egress-queue") == 0) {
            int iface_label = atoi(argv[2]);
            PPassPortStatus &status = port_status_map_[iface_label];
            status.egress_queue_ = dynamic_cast<Queue*>(TclObject::lookup(argv[3]));
            if (status.egress_queue_ == nullptr) {
                std::cerr << "DestHashClassifier::command could not find REDQueue " << argv[3] << "\n";
                return TCL_ERROR;
            }
            return TCL_OK;
        }

        if (strcmp(argv[1], "set-peer-id") == 0) {
            int iface_label = atoi(argv[2]);
            PPassPortStatus &status = port_status_map_[iface_label];
            status.peer_id_ = atoi(argv[3]);
            return TCL_OK;
        }

        if (strcmp(argv[1], "set-pqlen-integrator") == 0) {
            int iface_label = atoi(argv[2]);
            PPassPortStatus &status = port_status_map_[iface_label];

            status.pqlenInt_ = (Integrator *)TclObject::lookup(argv[3]);
            if (status.pqlenInt_ == nullptr)
                return (TCL_ERROR);
            return (TCL_OK);
        }
	}
    if (argc == 2) {
        if (strcmp(argv[1], "enable-ppass") == 0) {
            enable_ppass_ = true;
            return TCL_OK;
        }
    }
	if (argc == 3) {
        if (strcmp(argv[1], "start-sample-pqlen") == 0) {
            if (!sample_timer_)
                return TCL_ERROR;
            sample_timer_->sched(atof(argv[2]));
            return TCL_OK;
        }
        if (strcmp(argv[1], "sample-file") == 0) {
            if (sample_stream_.is_open())
                sample_stream_.close();
            sample_file_ = argv[2];
            sample_stream_.open(sample_file_.c_str(),
                                std::ios::out | std::ios::trunc);
            if (!sample_stream_.is_open()) {
                std::cerr << "DestHashClassifier::command could not open " << sample_file_ << " for writing\n";
                return TCL_ERROR;
            }
            return (TCL_OK);
        }
    }
	return(HashClassifier::command(argc, argv));
} // command


