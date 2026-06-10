#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_dcerpc_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_DCERPC, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_dcerpc(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* DCERPC RPC Header (minimum 16 bytes):
     *   [0]  version (0x05)
     *   [1]  pkt_type (0x00-0x0F, i.e. < 16)
     *   [2]  frag_attr (not a type check)
     *   [3]  auth_length
     * The previous check on payload[2] < 16 was wrong — pkt_type is at [1].
     * This caused most DCERPC packets to be missed (nDPI: 34827 vs MMT: 23). */
    if ((packet->tcp != NULL)
            && (packet->payload_packet_len >= 16)
            && ((ntohs(packet->tcp->source) == 135) || (ntohs(packet->tcp->dest) == 135))
            && (packet->payload[0] == 0x05) /* version 5 */
            && (packet->payload[1] < 16)    /* Packet type (was payload[2]) */
            ) {
        MMT_LOG(MMT_PROTOCOL_DCERPC, MMT_LOG_DEBUG, "DCERPC match\n");
        mmt_int_dcerpc_add_connection(ipacket);
        return;
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DCERPC);
}

int mmt_check_dcerpc(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* Same corrected threshold: payload[1] < 16 for pkt_type */
        if ((packet->payload_packet_len >= 16)
                && ((ntohs(packet->tcp->source) == 135) || (ntohs(packet->tcp->dest) == 135))
                && (packet->payload[0] == 0x05) /* version 5 */
                && (packet->payload[1] < 16)    /* Packet type (was payload[2]) */
                ) {
            MMT_LOG(MMT_PROTOCOL_DCERPC, MMT_LOG_DEBUG, "DCERPC match\n");
            mmt_int_dcerpc_add_connection(ipacket);
            return 1;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DCERPC);
    }
    return 0;
}

void mmt_init_classify_me_dcerpc() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DCERPC); //BW: check this out
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_DCERPC);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dcerpc_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DCERPC, PROTO_DCERPC_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_dcerpc();
        
        return register_protocol(protocol_struct, PROTO_DCERPC);
    } else {
        return 0;
    }
}
