#ifndef __CDOC2_H__
#define __CDOC2_H__

#include <string_view>

namespace libcdoc {
namespace CDoc2 {

static constexpr std::string_view LABEL = "CDOC\x02";
static constexpr std::string_view CEK = "CDOC20cek";
static constexpr std::string_view HMAC = "CDOC20hmac";
static constexpr std::string_view KEK = "CDOC20kek";
static constexpr std::string_view KEKPREMASTER = "CDOC20kekpremaster";
static constexpr std::string_view PAYLOAD = "CDOC20payload";
static constexpr std::string_view SALT = "CDOC20salt";

static constexpr int KEY_LEN = 32;
static constexpr int NONCE_LEN = 12;

static constexpr int KEYLABELVERSION = 1;

// Get salt bitstring for HKDF expand method
std::string getSaltForExpand(const std::string& label);

// Get salt bitstring for HKDF expand method
std::string getSaltForExpand(const std::vector<uint8_t>& key_material, const std::vector<uint8_t>& rcpt_key);


} // namespace CDoc2
} // namespace libcdoc

#endif
