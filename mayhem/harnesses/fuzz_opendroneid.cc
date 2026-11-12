// Fuzzes Kismet's ASTM F3411 / OpenDroneID Remote ID decoder (uav_parsers/opendroneid.cc).
// Input byte 0 selects the transport framing (raw message, BLE service data, Wi-Fi vendor IE, NAN
// attributes); the rest is the payload.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "uav_parsers/opendroneid.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return -1;

    const uint8_t *p = data + 1;
    const size_t n = size - 1;
    std::vector<odid::message> msgs;
    uint8_t counter = 0;

    switch (data[0] % 5) {
        case 0: {
            odid::message m;
            if (odid::decode_message(p, n, m)) {
                odid::ua_type_str(m.basic_id.ua_type);
                odid::id_type_str(m.basic_id.id_type);
                odid::status_str(m.location.status);
            }
            break;
        }
        case 1: odid::decode_messages(p, n, msgs); break;
        case 2: odid::decode_ble_service_data(p, n, counter, msgs); break;
        case 3: odid::decode_wifi_vendor_ie(p, n, counter, msgs); break;
        case 4: odid::decode_nan_attributes(p, n, counter, msgs); break;
    }

    return 0;
}
