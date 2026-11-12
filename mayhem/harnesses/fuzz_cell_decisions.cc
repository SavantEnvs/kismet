// Fuzzes the cell PHY's decision layer (phy_cell_decisions.cc): the validation of the untrusted JSON a
// capture helper (AT / DIAG) emits, the key/name/channel derivation built from it, and the DIAG
// CellSecurity alert rules. Input is the helper's JSON text.
#include <cstddef>
#include <cstdint>
#include <string>

#include "nlohmann/json.hpp"
#include "phy_cell_decisions.h"

using namespace cell_decisions;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nlohmann::json j = nlohmann::json::parse(data, data + size, nullptr, false);
    if (j.is_discarded() || !j.is_object())
        return -1;

    const std::string rat = (j.contains("rat") && j["rat"].is_string()) ? j["rat"].get<std::string>() : std::string();
    const cell_fields_t f = cell_fields(j);
    const plmn_t plmn = plmn_from_json(j);

    if (f.tac && f.cell_id) {
        const bool have_earfcn = f.earfcn.has_value();
        const uint32_t earfcn = have_earfcn ? static_cast<uint32_t>(*f.earfcn) : 0;
        const cell_key_t key = derive_key(rat, plmn, *f.tac, *f.cell_id, f.pci.value_or(-1),
                have_earfcn, earfcn);
        device_name(key, rat, f.pci.value_or(-1), earfcn, static_cast<int>(f.band.value_or(0)));
        if (f.pci && have_earfcn)
            pci_promotion(rat, *f.pci, true, earfcn, true);
        uint8_t mac[6];
        cell_key_to_mac_bytes(key.key, mac);
    }

    if (f.earfcn) {
        const uint32_t earfcn = static_cast<uint32_t>(*f.earfcn);
        arfcn_to_khz(rat, earfcn);
        channel_string(rat, static_cast<int>(f.band.value_or(0)), true, earfcn);
        carrier_token(rat, earfcn);
        label_band(rat, 0, static_cast<int>(f.band.value_or(0)), arfcn_to_khz(rat, earfcn));
        earfcn_to_band(earfcn);
    }

    if (f.rsrp)
        have_usable_rsrp(true, static_cast<int>(*f.rsrp));

    security_alerts(j);

    return 0;
}
