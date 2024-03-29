/*
 * wpa_supplicant - WPA/RSN IE and KDE processing
 * Copyright (c) 2003-2008, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "wpa.h"
#include "pmksa_cache.h"
#include "ieee802_11_defs.h"
#include "wpa_i.h"
#include "wpa_ie.h"


static int wpa_selector_to_bitfield(const u8 *s)
{
        if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_NONE)
                return WPA_CIPHER_NONE;
        if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_WEP40)
                return WPA_CIPHER_WEP40;
        if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_TKIP)
                return WPA_CIPHER_TKIP;
        if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_CCMP)
                return WPA_CIPHER_CCMP;
        if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_WEP104)
                return WPA_CIPHER_WEP104;
        return 0;
}


static int wpa_key_mgmt_to_bitfield(const u8 *s)
{
        if (RSN_SELECTOR_GET(s) == WPA_AUTH_KEY_MGMT_UNSPEC_802_1X)
                return WPA_KEY_MGMT_IEEE8021X;
        if (RSN_SELECTOR_GET(s) == WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X)
                return WPA_KEY_MGMT_PSK;
        if (RSN_SELECTOR_GET(s) == WPA_AUTH_KEY_MGMT_NONE)
                return WPA_KEY_MGMT_WPA_NONE;
#ifdef CONFIG_CCKM
        if (RSN_SELECTOR_GET(s) == WPA_AUTH_KEY_MGMT_CCKM)
                return WPA_KEY_MGMT_CCKM;
#endif
        return 0;
}


static int wpa_parse_wpa_ie_wpa(const u8 *wpa_ie, size_t wpa_ie_len,
                                struct wpa_ie_data *data)
{
        const struct wpa_ie_hdr *hdr;
        const u8 *pos;
        int left;
        int i, count;

        os_memset(data, 0, sizeof(*data));
        data->proto = WPA_PROTO_WPA;
        data->pairwise_cipher = WPA_CIPHER_TKIP;
        data->group_cipher = WPA_CIPHER_TKIP;
        data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
        data->capabilities = 0;
        data->pmkid = NULL;
        data->num_pmkid = 0;
        data->mgmt_group_cipher = 0;

        if (wpa_ie_len == 0) {
                /* No WPA IE - fail silently */
                return -1;
        }

        if (wpa_ie_len < sizeof(struct wpa_ie_hdr)) {
                wpa_printf(MSG_DEBUG, "%s: ie len too short %lu",
                           __func__, (unsigned long) wpa_ie_len);
                return -1;
        }

        hdr = (const struct wpa_ie_hdr *) wpa_ie;

        if (hdr->elem_id != WLAN_EID_VENDOR_SPECIFIC ||
            hdr->len != wpa_ie_len - 2 ||
            RSN_SELECTOR_GET(hdr->oui) != WPA_OUI_TYPE ||
            WPA_GET_LE16(hdr->version) != WPA_VERSION) {
                wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",
                           __func__);
                return -1;
        }

        pos = (const u8 *) (hdr + 1);
        left = wpa_ie_len - sizeof(*hdr);

        if (left >= WPA_SELECTOR_LEN) {
                data->group_cipher = wpa_selector_to_bitfield(pos);
                pos += WPA_SELECTOR_LEN;
                left -= WPA_SELECTOR_LEN;
        } else if (left > 0) {
                wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",
                           __func__, left);
                return -1;
        }

        if (left >= 2) {
                data->pairwise_cipher = 0;
                count = WPA_GET_LE16(pos);
                pos += 2;
                left -= 2;
                if (count == 0 || left < count * WPA_SELECTOR_LEN) {
                        wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), "
                                   "count %u left %u", __func__, count, left);
                        return -1;
                }
                for (i = 0; i < count; i++) {
                        data->pairwise_cipher |= wpa_selector_to_bitfield(pos);
                        pos += WPA_SELECTOR_LEN;
                        left -= WPA_SELECTOR_LEN;
                }
        } else if (left == 1) {
                wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",
                           __func__);
                return -1;
        }

        if (left >= 2) {
                data->key_mgmt = 0;
                count = WPA_GET_LE16(pos);
                pos += 2;
                left -= 2;
                if (count == 0 || left < count * WPA_SELECTOR_LEN) {
                        wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
                                   "count %u left %u", __func__, count, left);
                        return -1;
                }
                for (i = 0; i < count; i++) {
                        data->key_mgmt |= wpa_key_mgmt_to_bitfield(pos);
                        pos += WPA_SELECTOR_LEN;
                        left -= WPA_SELECTOR_LEN;
                }
        } else if (left == 1) {
                wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",
                           __func__);
                return -1;
        }

        if (left >= 2) {
                data->capabilities = WPA_GET_LE16(pos);
                pos += 2;
                left -= 2;
        }

        if (left > 0) {
                wpa_printf(MSG_DEBUG, "%s: ie has %u trailing bytes - ignored",
                           __func__, left);
        }

        return 0;
}


/**
 * wpa_parse_wpa_ie - Parse WPA/RSN IE
 * @wpa_ie: Pointer to WPA or RSN IE
 * @wpa_ie_len: Length of the WPA/RSN IE
 * @data: Pointer to data area for parsing results
 * Returns: 0 on success, -1 on failure
 *
 * Parse the contents of WPA or RSN IE and write the parsed data into data.
 */
int wpa_parse_wpa_ie(const u8 *wpa_ie, size_t wpa_ie_len,
                     struct wpa_ie_data *data)
{
        if (wpa_ie_len >= 1 && wpa_ie[0] == WLAN_EID_RSN)
                return wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
        else
                return wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, data);
}


static int wpa_gen_wpa_ie_wpa(u8 *wpa_ie, size_t wpa_ie_len,
                              int pairwise_cipher, int group_cipher,
                              int key_mgmt)
{
        u8 *pos;
        struct wpa_ie_hdr *hdr;

        if (wpa_ie_len < sizeof(*hdr) + WPA_SELECTOR_LEN +
            2 + WPA_SELECTOR_LEN + 2 + WPA_SELECTOR_LEN)
                return -1;

        hdr = (struct wpa_ie_hdr *) wpa_ie;
        hdr->elem_id = WLAN_EID_VENDOR_SPECIFIC;
        RSN_SELECTOR_PUT(hdr->oui, WPA_OUI_TYPE);
        WPA_PUT_LE16(hdr->version, WPA_VERSION);
        pos = (u8 *) (hdr + 1);

        if (group_cipher == WPA_CIPHER_CCMP) {
                RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_CCMP);
        } else if (group_cipher == WPA_CIPHER_TKIP) {
                RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_TKIP);
        } else if (group_cipher == WPA_CIPHER_WEP104) {
                RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_WEP104);
        } else if (group_cipher == WPA_CIPHER_WEP40) {
                RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_WEP40);
        } else {
                wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
                           group_cipher);
                return -1;
        }
        pos += WPA_SELECTOR_LEN;

        *pos++ = 1;
        *pos++ = 0;
        if (pairwise_cipher == WPA_CIPHER_CCMP) {
                RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_CCMP);
        } else if (pairwise_cipher == WPA_CIPHER_TKIP) {
                RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_TKIP);
        } else if (pairwise_cipher == WPA_CIPHER_NONE) {
                RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_NONE);
        } else {
                wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
                           pairwise_cipher);
                return -1;
        }
        pos += WPA_SELECTOR_LEN;

        *pos++ = 1;
        *pos++ = 0;
        if (key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
                RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X);
        } else if (key_mgmt == WPA_KEY_MGMT_PSK) {
                RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X);
        } else if (key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
                RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_NONE);
#ifdef CONFIG_CCKM
        } else if (key_mgmt == WPA_KEY_MGMT_CCKM) {
                RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_CCKM);
#endif
        } else {
                wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
                           key_mgmt);
                return -1;
        }
        pos += WPA_SELECTOR_LEN;

        /* WPA Capabilities; use defaults, so no need to include it */

        hdr->len = (pos - wpa_ie) - 2;

        WPA_ASSERT((size_t) (pos - wpa_ie) <= wpa_ie_len);

        return pos - wpa_ie;
}


static int wpa_gen_wpa_ie_rsn(u8 *rsn_ie, size_t rsn_ie_len,
                              int pairwise_cipher, int group_cipher,
                              int key_mgmt, int mgmt_group_cipher,
                              struct wpa_sm *sm)
{
#ifndef CONFIG_NO_WPA2
        u8 *pos;
        struct rsn_ie_hdr *hdr;
        u16 capab;

        if (rsn_ie_len < sizeof(*hdr) + RSN_SELECTOR_LEN +
            2 + RSN_SELECTOR_LEN + 2 + RSN_SELECTOR_LEN + 2 +
            (sm->cur_pmksa ? 2 + PMKID_LEN : 0)) {
                wpa_printf(MSG_DEBUG, "RSN: Too short IE buffer (%lu bytes)",
                           (unsigned long) rsn_ie_len);
                return -1;
        }

        hdr = (struct rsn_ie_hdr *) rsn_ie;
        hdr->elem_id = WLAN_EID_RSN;
        WPA_PUT_LE16(hdr->version, RSN_VERSION);
        pos = (u8 *) (hdr + 1);

        if (group_cipher == WPA_CIPHER_CCMP) {
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_CCMP);
        } else if (group_cipher == WPA_CIPHER_TKIP) {
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_TKIP);
        } else if (group_cipher == WPA_CIPHER_WEP104) {
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_WEP104);
        } else if (group_cipher == WPA_CIPHER_WEP40) {
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_WEP40);
        } else {
                wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
                           group_cipher);
                return -1;
        }
        pos += RSN_SELECTOR_LEN;

        *pos++ = 1;
        *pos++ = 0;
        if (pairwise_cipher == WPA_CIPHER_CCMP) {
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_CCMP);
        } else if (pairwise_cipher == WPA_CIPHER_TKIP) {
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_TKIP);
        } else if (pairwise_cipher == WPA_CIPHER_NONE) {
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_NONE);
        } else {
                wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
                           pairwise_cipher);
                return -1;
        }
        pos += RSN_SELECTOR_LEN;

        *pos++ = 1;
        *pos++ = 0;
        if (key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
                RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X);
        } else if (key_mgmt == WPA_KEY_MGMT_PSK) {
                RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X);
#ifdef CONFIG_IEEE80211R
        } else if (key_mgmt == WPA_KEY_MGMT_FT_IEEE8021X) {
                RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_802_1X);
        } else if (key_mgmt == WPA_KEY_MGMT_FT_PSK) {
                RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_PSK);
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
        } else if (key_mgmt == WPA_KEY_MGMT_IEEE8021X_SHA256) {
                RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_802_1X_SHA256);
        } else if (key_mgmt == WPA_KEY_MGMT_PSK_SHA256) {
                RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_PSK_SHA256);
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_CCKM
        } else if (key_mgmt == WPA_KEY_MGMT_CCKM) {
                RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_CCKM);
#endif
        } else {
                wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
                           key_mgmt);
                return -1;
        }
        pos += RSN_SELECTOR_LEN;

        /* RSN Capabilities */
        capab = 0;
#ifdef CONFIG_IEEE80211W
        if (mgmt_group_cipher == WPA_CIPHER_AES_128_CMAC)
                capab |= WPA_CAPABILITY_MFPC;
#endif /* CONFIG_IEEE80211W */
        WPA_PUT_LE16(pos, capab);
        pos += 2;

        if (sm->cur_pmksa) {
                /* PMKID Count (2 octets, little endian) */
                *pos++ = 1;
                *pos++ = 0;
                /* PMKID */
                os_memcpy(pos, sm->cur_pmksa->pmkid, PMKID_LEN);
                pos += PMKID_LEN;
        }

#ifdef CONFIG_IEEE80211W
        if (mgmt_group_cipher == WPA_CIPHER_AES_128_CMAC) {
                if (!sm->cur_pmksa) {
                        /* PMKID Count */
                        WPA_PUT_LE16(pos, 0);
                        pos += 2;
                }

                /* Management Group Cipher Suite */
                RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_AES_128_CMAC);
                pos += RSN_SELECTOR_LEN;
        }
#endif /* CONFIG_IEEE80211W */

        hdr->len = (pos - rsn_ie) - 2;

        WPA_ASSERT((size_t) (pos - rsn_ie) <= rsn_ie_len);

        return pos - rsn_ie;
#else /* CONFIG_NO_WPA2 */
        return -1;
#endif /* CONFIG_NO_WPA2 */
}


/**
 * wpa_gen_wpa_ie - Generate WPA/RSN IE based on current security policy
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @wpa_ie: Pointer to memory area for the generated WPA/RSN IE
 * @wpa_ie_len: Maximum length of the generated WPA/RSN IE
 * Returns: Length of the generated WPA/RSN IE or -1 on failure
 */
int wpa_gen_wpa_ie(struct wpa_sm *sm, u8 *wpa_ie, size_t wpa_ie_len)
{
        if (sm->proto == WPA_PROTO_RSN)
                return wpa_gen_wpa_ie_rsn(wpa_ie, wpa_ie_len,
                                          sm->pairwise_cipher,
                                          sm->group_cipher,
                                          sm->key_mgmt, sm->mgmt_group_cipher,
                                          sm);
        else
                return wpa_gen_wpa_ie_wpa(wpa_ie, wpa_ie_len,
                                          sm->pairwise_cipher,
                                          sm->group_cipher,
                                          sm->key_mgmt);
}


/**
 * wpa_parse_generic - Parse EAPOL-Key Key Data Generic IEs
 * @pos: Pointer to the IE header
 * @end: Pointer to the end of the Key Data buffer
 * @ie: Pointer to parsed IE data
 * Returns: 0 on success, 1 if end mark is found, -1 on failure
 */
static int wpa_parse_generic(const u8 *pos, const u8 *end,
                             struct wpa_eapol_ie_parse *ie)
{
        if (pos[1] == 0)
                return 1;

        if (pos[1] >= 6 &&
            RSN_SELECTOR_GET(pos + 2) == WPA_OUI_TYPE &&
            pos[2 + WPA_SELECTOR_LEN] == 1 &&
            pos[2 + WPA_SELECTOR_LEN + 1] == 0) {
                ie->wpa_ie = pos;
                ie->wpa_ie_len = pos[1] + 2;
                return 0;
        }

        if (pos + 1 + RSN_SELECTOR_LEN < end &&
            pos[1] >= RSN_SELECTOR_LEN + PMKID_LEN &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_PMKID) {
                ie->pmkid = pos + 2 + RSN_SELECTOR_LEN;
                return 0;
        }

        if (pos[1] > RSN_SELECTOR_LEN + 2 &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_GROUPKEY) {
                ie->gtk = pos + 2 + RSN_SELECTOR_LEN;
                ie->gtk_len = pos[1] - RSN_SELECTOR_LEN;
                return 0;
        }

        if (pos[1] > RSN_SELECTOR_LEN + 2 &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_MAC_ADDR) {
                ie->mac_addr = pos + 2 + RSN_SELECTOR_LEN;
                ie->mac_addr_len = pos[1] - RSN_SELECTOR_LEN;
                return 0;
        }

#ifdef CONFIG_PEERKEY
        if (pos[1] > RSN_SELECTOR_LEN + 2 &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_SMK) {
                ie->smk = pos + 2 + RSN_SELECTOR_LEN;
                ie->smk_len = pos[1] - RSN_SELECTOR_LEN;
                return 0;
        }

        if (pos[1] > RSN_SELECTOR_LEN + 2 &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_NONCE) {
                ie->nonce = pos + 2 + RSN_SELECTOR_LEN;
                ie->nonce_len = pos[1] - RSN_SELECTOR_LEN;
                return 0;
        }

        if (pos[1] > RSN_SELECTOR_LEN + 2 &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_LIFETIME) {
                ie->lifetime = pos + 2 + RSN_SELECTOR_LEN;
                ie->lifetime_len = pos[1] - RSN_SELECTOR_LEN;
                return 0;
        }

        if (pos[1] > RSN_SELECTOR_LEN + 2 &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_ERROR) {
                ie->error = pos + 2 + RSN_SELECTOR_LEN;
                ie->error_len = pos[1] - RSN_SELECTOR_LEN;
                return 0;
        }
#endif /* CONFIG_PEERKEY */

#ifdef CONFIG_IEEE80211W
        if (pos[1] > RSN_SELECTOR_LEN + 2 &&
            RSN_SELECTOR_GET(pos + 2) == RSN_KEY_DATA_IGTK) {
                ie->igtk = pos + 2 + RSN_SELECTOR_LEN;
                ie->igtk_len = pos[1] - RSN_SELECTOR_LEN;
                return 0;
        }
#endif /* CONFIG_IEEE80211W */

        return 0;
}


/**
 * wpa_supplicant_parse_ies - Parse EAPOL-Key Key Data IEs
 * @buf: Pointer to the Key Data buffer
 * @len: Key Data Length
 * @ie: Pointer to parsed IE data
 * Returns: 0 on success, -1 on failure
 */
int wpa_supplicant_parse_ies(const u8 *buf, size_t len,
                             struct wpa_eapol_ie_parse *ie)
{
        const u8 *pos, *end;
        int ret = 0;

        os_memset(ie, 0, sizeof(*ie));
        for (pos = buf, end = pos + len; pos + 1 < end; pos += 2 + pos[1]) {
                if (pos[0] == 0xdd &&
                    ((pos == buf + len - 1) || pos[1] == 0)) {
                        /* Ignore padding */
                        break;
                }
                if (pos + 2 + pos[1] > end) {
                        wpa_printf(MSG_DEBUG, "WPA: EAPOL-Key Key Data "
                                   "underflow (ie=%d len=%d pos=%d)",
                                   pos[0], pos[1], (int) (pos - buf));
                        wpa_hexdump_key(MSG_DEBUG, "WPA: Key Data",
                                        buf, len);
                        ret = -1;
                        break;
                }
                if (*pos == WLAN_EID_RSN) {
                        ie->rsn_ie = pos;
                        ie->rsn_ie_len = pos[1] + 2;
#ifdef CONFIG_IEEE80211R
                } else if (*pos == WLAN_EID_MOBILITY_DOMAIN) {
                        ie->mdie = pos;
                        ie->mdie_len = pos[1] + 2;
#endif /* CONFIG_IEEE80211R */
                } else if (*pos == WLAN_EID_VENDOR_SPECIFIC) {
                        ret = wpa_parse_generic(pos, end, ie);
                        if (ret < 0)
                                break;
                        if (ret > 0) {
                                ret = 0;
                                break;
                        }
                } else {
                        wpa_hexdump(MSG_DEBUG, "WPA: Unrecognized EAPOL-Key "
                                    "Key Data IE", pos, 2 + pos[1]);
                }
        }

        return ret;
}
