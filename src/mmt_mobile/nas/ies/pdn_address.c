#include "../util/decoder.h"
#include "pdn_address.h"

int nas_decode_pdn_address(nas_pdn_address_t *addr, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
  int decoded = 0;
  uint8_t ielen = 0;
  int decode_result;

  if (iei > 0) {
    CHECK_IEI_DECODER(iei, *buffer);
    decoded++;
  }

  IES_DECODE_U8( buffer, decoded, ielen );

  CHECK_LENGTH_DECODER(len - decoded, ielen);

  // F-BUG-206: reject ielen=0 before reading pdn_type byte (enabler for 202)
  if (ielen == 0) {
    errorCodeDecoder = DECODE_BUFFER_TOO_SHORT;
    return DECODE_BUFFER_TOO_SHORT;
  }
  CHECK_LENGTH_DECODER(len - decoded, 1);

  DECODE_U8( buffer+decoded, addr->pdn_type_value, decoded );
  //get 4 high bits
  addr->pdn_type_value &= 0b111;

  // ielen includes the pdn_type byte; address payload is the remainder
  addr->pdn_address_information.len  = ielen - 1;
  addr->pdn_address_information.data = buffer + decoded;

  // F-BUG-202: bound address read by pdn_type-implied minimum
  if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4) {
    CHECK_LENGTH_DECODER(addr->pdn_address_information.len, 4);
  } else if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV6) {
    CHECK_LENGTH_DECODER(addr->pdn_address_information.len, 8);
  } else if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4V6) {
    CHECK_LENGTH_DECODER(addr->pdn_address_information.len, 12);
  }

  decoded += addr->pdn_address_information.len;

  return decoded;
}

