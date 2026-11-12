// Fuzzes Kismet's Bluetooth LE advertisement decoders (bluetooth_parsers/*): the manufacturer-data,
// service-data and AD-type payload decoders that phy_bluetooth hands raw advertisement bytes to.
// Input byte 0 selects the decoder; the rest is its payload.
#include <cstddef>
#include <cstdint>
#include <string>

#include "bluetooth_parsers/bt_assigned.h"
#include "bluetooth_parsers/btle_adtypes.h"
#include "bluetooth_parsers/btle_battery.h"
#include "bluetooth_parsers/btle_beacon.h"
#include "bluetooth_parsers/btle_continuity.h"
#include "bluetooth_parsers/btle_ranging.h"
#include "bluetooth_parsers/btle_sensor.h"
#include "bluetooth_parsers/btle_tracker.h"
#include "bluetooth_parsers/btle_vendor.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return -1;

    const uint8_t sel = data[0];
    const uint8_t *p = data + 1;
    const size_t n = size - 1;

    switch (sel % 40) {
        case 0: { btle_tracker::smarttag_info o; btle_tracker::decode_samsung_smarttag(p, n, o); break; }
        case 1: { btle_tracker::findmy_info o; btle_tracker::decode_apple_findmy(p, n, o); break; }
        case 2: { btle_tracker::fmdn_info o; btle_tracker::decode_google_fmdn(p, n, o); break; }
        case 3: { btle_tracker::dult_info o; btle_tracker::decode_dult(p, n, o); break; }
        case 4: { btle_tracker::identified_info o; btle_tracker::decode_identified_tracker(p, n, o); break; }
        case 5: { btle_adtypes::mesh_beacon o; btle_adtypes::decode_mesh_beacon(p, n, o); break; }
        case 6: { btle_adtypes::mesh_proxy o; btle_adtypes::decode_mesh_proxy(p, n, o); break; }
        case 7: { btle_adtypes::mesh_provisioning o; btle_adtypes::decode_mesh_provisioning(p, n, o); break; }
        case 8: { std::string o; btle_adtypes::decode_broadcast_name(p, n, o); break; }
        case 9: { btle_adtypes::broadcast_audio o; btle_adtypes::decode_broadcast_audio(p, n, o); break; }
        case 10: { btle_adtypes::public_broadcast o; btle_adtypes::decode_public_broadcast(p, n, o); break; }
        case 11: { btle_adtypes::unicast_announcement o; btle_adtypes::decode_unicast_announcement(p, n, o); break; }
        case 12: { std::string o; btle_adtypes::decode_resolvable_set_id(p, n, o); break; }
        case 13: { std::string o; btle_adtypes::decode_uri(p, n, o); break; }
        case 14: { btle_adtypes::transport_discovery o; btle_adtypes::decode_transport_discovery(p, n, o); break; }
        case 15: { std::string o; btle_adtypes::decode_le_features(p, n, o); break; }
        case 16: { uint64_t o; btle_adtypes::decode_adv_interval(p, n, o); break; }
        case 17: { uint64_t o; btle_adtypes::decode_adv_interval_long(p, n, o); break; }
        case 18: { btle_adtypes::conn_interval_range o; btle_adtypes::decode_conn_interval_range(p, n, o); break; }
        case 19: { btle_adtypes::le_role o; btle_adtypes::decode_le_role(p, n, o); break; }
        case 20: { btle_adtypes::indoor_positioning o; btle_adtypes::decode_indoor_positioning(p, n, o); break; }
        case 21: { btle_battery::info o; btle_battery::decode_service_data(p, n, o); break; }
        case 22: { btle_battery::info o; btle_battery::decode_manuf_data(p, n, o); break; }
        case 23: { btle_beacon::info o; btle_beacon::decode_manuf_data(p, n, o); break; }
        case 24: { btle_beacon::info o; btle_beacon::decode_service_data(p, n, o); break; }
        case 25: {
            btle_continuity::info o;
            if (btle_continuity::decode_manuf_data(p, n, o))
                btle_continuity::types_str(o.seen_types);
            break;
        }
        case 26: { btle_ranging::info o; btle_ranging::decode_service_data(p, n, o); break; }
        case 27: { btle_ranging::info o; btle_ranging::decode_manuf_data(p, n, o); break; }
        case 28: { btle_sensor::info o; btle_sensor::decode_service_data(p, n, o); break; }
        case 29: { btle_sensor::info o; btle_sensor::decode_manuf_data(p, n, o); break; }
        case 30: { btle_vendor::microsoft_info o; btle_vendor::decode_microsoft(p, n, o); break; }
        case 31: { btle_vendor::fastpair_info o; btle_vendor::decode_fastpair(p, n, o); break; }
        case 32: { btle_vendor::matter_info o; btle_vendor::decode_matter(p, n, o); break; }
        case 33: btle_vendor::decode_ccc_digital_key(p, n); break;
        case 34: {
            // Name-keyed lookups take arbitrary advertised strings
            btle_vendor::vehicle_from_name(std::string(reinterpret_cast<const char *>(p), n));
            break;
        }
        case 35: {
            if (n >= 4) {
                uint32_t cod = p[0] | (p[1] << 8) | (p[2] << 16) | (static_cast<uint32_t>(p[3]) << 24);
                bt_assigned::cod_service_names(cod);
                bt_assigned::cod_minor_name(p[0], p[1]);
            }
            break;
        }
        case 36: if (n >= 2) bt_assigned::appearance_name(p[0] | (p[1] << 8)); break;
        case 37: if (n >= 2) btle_adtypes::mesh_oob_info_str(p[0] | (p[1] << 8)); break;
        case 38: if (n >= 2) btle_adtypes::audio_context_str(p[0] | (p[1] << 8)); break;
        case 39: {
            if (n >= 3) {
                btle_ranging::from_tx_power(static_cast<int8_t>(p[0]));
                btle_ranging::estimate_distance(static_cast<int8_t>(p[1]), static_cast<int8_t>(p[2]), 2.0);
            }
            break;
        }
    }

    return 0;
}
