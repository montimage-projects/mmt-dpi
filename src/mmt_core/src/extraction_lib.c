#include "extraction_lib.h"
#include "mmt_core.h"

int silent_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {
    return 0;
}

int general_byte_to_byte_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0 || attr_data_len <= 0) return 0;
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + (size_t)attr_data_len > packet->p_hdr->caplen) return 0;

    memcpy((u_char *) extracted_data->data, (char *) & packet->data[proto_offset + attribute_offset], attr_data_len);
    return 1;
}

int general_short_extraction_with_ordering_change(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint16_t) > packet->p_hdr->caplen) return 0;

    *((unsigned short *) extracted_data->data) = ntohs(*((unsigned short *) & packet->data[proto_offset + attribute_offset]));
    return 1;
}

int general_int_extraction_with_ordering_change(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint32_t) > packet->p_hdr->caplen) return 0;

    *((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) & packet->data[proto_offset + attribute_offset]));
    return 1;
}

int general_char_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint8_t) > packet->p_hdr->caplen) return 0;

    *((unsigned char *) extracted_data->data) = *((unsigned char *) & packet->data[proto_offset + attribute_offset]);
    return 1;
}

int general_short_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint16_t) > packet->p_hdr->caplen) return 0;

    *((unsigned short *) extracted_data->data) = *((unsigned short *) & packet->data[proto_offset + attribute_offset]);
    return 1;
}

int general_int_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint32_t) > packet->p_hdr->caplen) return 0;

    *((unsigned int *) extracted_data->data) = *((unsigned int *) & packet->data[proto_offset + attribute_offset]);
    return 1;
}

