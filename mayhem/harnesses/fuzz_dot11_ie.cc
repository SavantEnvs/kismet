// Fuzzes Kismet's 802.11 information-element parsers (dot11_parsers/*).
// Input byte 0 selects the entry: 0 runs the real flow (split a tagged-parameter blob, then hand each
// tag to the parser kismet uses for that tag number); any other value runs a single parser directly on
// the rest of the input, so every parser is reachable without a valid enclosing frame.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include <kaitai/kaitaistream.h>

#include "dot11_action.h"
#include "dot11_ie.h"
#include "dot11_ie_113_mesh_config.h"
#include "dot11_ie_11_qbss.h"
#include "dot11_ie_127_extended_capabilities.h"
#include "dot11_ie_133_cisco_ccx.h"
#include "dot11_ie_150_cisco_powerlevel.h"
#include "dot11_ie_150_vendor.h"
#include "dot11_ie_191_vht_cap.h"
#include "dot11_ie_192_vht_op.h"
#include "dot11_ie_213_s1g_beacon_compat.h"
#include "dot11_ie_214_short_beacon_interval.h"
#include "dot11_ie_217_s1g_capabilities.h"
#include "dot11_ie_221_cisco_client_mfp.h"
#include "dot11_ie_221_dji_droneid.h"
#include "dot11_ie_221_mikrotik.h"
#include "dot11_ie_221_ms_wmm.h"
#include "dot11_ie_221_ms_wps.h"
#include "dot11_ie_221_rsn_pmkid.h"
#include "dot11_ie_221_ubnt_airmax_ac.h"
#include "dot11_ie_221_ubnt_airmax_m.h"
#include "dot11_ie_221_vendor.h"
#include "dot11_ie_221_wfa.h"
#include "dot11_ie_221_wfa_wpa.h"
#include "dot11_ie_221_wpa_transition.h"
#include "dot11_ie_232_s1g_operation.h"
#include "dot11_ie_255_ext_tag.h"
#include "dot11_ie_33_power.h"
#include "dot11_ie_35_tpc.h"
#include "dot11_ie_36_supported_channels.h"
#include "dot11_ie_37_csa.h"
#include "dot11_ie_45_ht_cap.h"
#include "dot11_ie_48_rsn.h"
#include "dot11_ie_52_rmm_neighbor.h"
#include "dot11_ie_54_mobility.h"
#include "dot11_ie_55_fastbss.h"
#include "dot11_ie_61_ht_op.h"
#include "dot11_ie_70_rm_capabilities.h"
#include "dot11_ie_71_mbssid.h"
#include "dot11_ie_7_country.h"
#include "dot11_p2p_ie.h"
#include "dot11_s1g.h"
#include "dot11_wpa_eap.h"

namespace {

template <typename T> void str_parser(const std::string& d) { T t; t.parse(d); }
template <typename T> void kstream_parser(const std::string& d) {
    T t;
    t.parse(std::make_shared<kaitai::kstream>(d));
}
template <typename T> void view_parser(const std::string& d) {
    T t;
    std::string_view v(d);
    t.parse(&v);
}

void action_parser(const std::string& d) {
    dot11_action t;
    kaitai::kstream ks(d);
    t.parse(ks);
}

using parser_fn = void (*)(const std::string&);

const parser_fn parsers[] = {
    str_parser<dot11_ie_113_mesh_config>,
    str_parser<dot11_ie_11_qbss>,
    kstream_parser<dot11_ie_127_extended>,
    str_parser<dot11_ie_133_cisco_ccx>,
    str_parser<dot11_ie_150_cisco_powerlevel>,
    str_parser<dot11_ie_150_vendor>,
    str_parser<dot11_ie_191_vht_cap>,
    str_parser<dot11_ie_192_vht_op>,
    view_parser<dot11_ie_213_s1g_beacon_compat>,
    str_parser<dot11_ie_214_short_beacon_interval>,
    view_parser<dot11_ie_217_s1g_capabilities>,
    str_parser<dot11_ie_221_cisco_client_mfp>,
    str_parser<dot11_ie_221_dji_droneid>,
    str_parser<dot11_ie_221_mikrotik>,
    str_parser<dot11_ie_221_ms_wmm>,
    str_parser<dot11_ie_221_ms_wps>,
    str_parser<dot11_ie_221_rsn_pmkid>,
    str_parser<dot11_ie_221_ubnt_airmax_ac>,
    str_parser<dot11_ie_221_ubnt_airmax_m>,
    str_parser<dot11_ie_221_vendor>,
    str_parser<dot11_ie_221_wfa>,
    str_parser<dot11_ie_221_wfa_wpa>,
    str_parser<dot11_ie_221_owe_transition>,
    str_parser<dot11_ie_232_s1g_operation>,
    str_parser<dot11_ie_255_ext>,
    str_parser<dot11_ie_33_power>,
    str_parser<dot11_ie_35_tpc>,
    kstream_parser<dot11_ie_36_supported_channels>,
    str_parser<dot11_ie_37_csa>,
    str_parser<dot11_ie_45_ht_cap>,
    str_parser<dot11_ie_48_rsn>,
    str_parser<dot11_ie_48_rsn_partial>,
    str_parser<dot11_ie_52_rmm>,
    str_parser<dot11_ie_54_mobility>,
    kstream_parser<dot11_ie_55_fastbss>,
    str_parser<dot11_ie_61_ht_op>,
    kstream_parser<dot11_ie_70_rm_cap>,
    str_parser<dot11_ie_71_mbssid>,
    str_parser<dot11_ie_7_country>,
    str_parser<dot11_wfa_p2p_ie>,
    view_parser<dot11_s1g>,
    str_parser<dot11_wpa_eap>,
    action_parser,
};
constexpr size_t num_parsers = sizeof(parsers) / sizeof(parsers[0]);

// Tag number -> parser, as phy_80211 dispatches them; 0 where kismet has no dedicated parser.
parser_fn parser_for_tag(uint8_t tag) {
    switch (tag) {
        case 7: return str_parser<dot11_ie_7_country>;
        case 11: return str_parser<dot11_ie_11_qbss>;
        case 33: return str_parser<dot11_ie_33_power>;
        case 35: return str_parser<dot11_ie_35_tpc>;
        case 36: return kstream_parser<dot11_ie_36_supported_channels>;
        case 37: return str_parser<dot11_ie_37_csa>;
        case 45: return str_parser<dot11_ie_45_ht_cap>;
        case 48: return str_parser<dot11_ie_48_rsn>;
        case 52: return str_parser<dot11_ie_52_rmm>;
        case 54: return str_parser<dot11_ie_54_mobility>;
        case 55: return kstream_parser<dot11_ie_55_fastbss>;
        case 61: return str_parser<dot11_ie_61_ht_op>;
        case 70: return kstream_parser<dot11_ie_70_rm_cap>;
        case 71: return str_parser<dot11_ie_71_mbssid>;
        case 113: return str_parser<dot11_ie_113_mesh_config>;
        case 127: return kstream_parser<dot11_ie_127_extended>;
        case 133: return str_parser<dot11_ie_133_cisco_ccx>;
        case 150: return str_parser<dot11_ie_150_vendor>;
        case 191: return str_parser<dot11_ie_191_vht_cap>;
        case 192: return str_parser<dot11_ie_192_vht_op>;
        case 213: return view_parser<dot11_ie_213_s1g_beacon_compat>;
        case 214: return str_parser<dot11_ie_214_short_beacon_interval>;
        case 217: return view_parser<dot11_ie_217_s1g_capabilities>;
        case 221: return str_parser<dot11_ie_221_vendor>;
        case 232: return str_parser<dot11_ie_232_s1g_operation>;
        case 255: return str_parser<dot11_ie_255_ext>;
        default: return nullptr;
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return -1;

    const uint8_t sel = data[0];
    const std::string body(reinterpret_cast<const char *>(data) + 1, size - 1);

    try {
        if (sel == 0) {
            dot11_ie ies;
            ies.parse(body);
            for (const auto& tag : ies.tags()) {
                parser_fn fn = parser_for_tag(tag.tag_num());
                if (fn == nullptr)
                    continue;
                try {
                    fn(tag.tag_data());
                } catch (...) {
                }
            }
        } else {
            parsers[(sel - 1) % num_parsers](body);
        }
    } catch (...) {
    }

    return 0;
}
