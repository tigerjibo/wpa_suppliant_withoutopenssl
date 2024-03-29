/*
 * wpa_supplicant - WPA definitions
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
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

#ifndef WPA_H
#define WPA_H

#include "defs.h"
#include "eapol_common.h"
#include "wpa_common.h"

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888e
#endif

#ifndef ETH_P_RSN_PREAUTH
#define ETH_P_RSN_PREAUTH 0x88c7
#endif

struct wpa_sm;
struct eapol_sm;
struct wpa_config_blob;
struct wpa_gtk_data {
  wpa_alg alg;
  int tx, key_rsc_len, keyidx;
  u8 gtk[32];
  u8 key_rsc[8];
  int gtk_len;
};


struct wpa_sm_ctx {
  void *ctx; /* pointer to arbitrary upper level context */

  void (*set_state)(void *ctx, wpa_states state);
  wpa_states (*get_state)(void *ctx);
  void (*deauthenticate)(void * ctx, int reason_code); 
  void (*disassociate)(void *ctx, int reason_code);
  int (*set_key)(void *ctx, wpa_alg alg,
           const u8 *addr, int key_idx, int set_tx,
           const u8 *seq, size_t seq_len,
           const u8 *key, size_t key_len);
  void * (*get_network_ctx)(void *ctx);
  int (*get_bssid)(void *ctx, u8 *bssid);
  int (*ether_send)(void *ctx, const u8 *dest, u16 proto, const u8 *buf,
        size_t len);
  int (*get_beacon_ie)(void *ctx);
  void (*cancel_auth_timeout)(void *ctx);
  u8 * (*alloc_eapol)(void *ctx, u8 type, const void *data, u16 data_len,
          size_t *msg_len, void **data_pos);
  int (*add_pmkid)(void *ctx, const u8 *bssid, const u8 *pmkid);
  int (*remove_pmkid)(void *ctx, const u8 *bssid, const u8 *pmkid);
  void (*set_config_blob)(void *ctx, struct wpa_config_blob *blob);
  const struct wpa_config_blob * (*get_config_blob)(void *ctx,
                const char *name);
  int (*mlme_setprotection)(void *ctx, const u8 *addr,
          int protection_type, int key_type);
  int (*update_ft_ies)(void *ctx, const u8 *md, const u8 *ies,
           size_t ies_len);
  int (*send_ft_action)(void *ctx, u8 action, const u8 *target_ap,
            const u8 *ies, size_t ies_len);
};


enum wpa_sm_conf_params {
  RSNA_PMK_LIFETIME /* dot11RSNAConfigPMKLifetime */,
  RSNA_PMK_REAUTH_THRESHOLD /* dot11RSNAConfigPMKReauthThreshold */,
  RSNA_SA_TIMEOUT /* dot11RSNAConfigSATimeout */,
  WPA_PARAM_PROTO,
  WPA_PARAM_PAIRWISE,
  WPA_PARAM_GROUP,
  WPA_PARAM_KEY_MGMT,
  WPA_PARAM_MGMT_GROUP,
  WPA_PARAM_RSN_ENABLED
};

struct rsn_supp_config {
  void *network_ctx;
  int peerkey_enabled;
  int allowed_pairwise_cipher; /* bitfield of WPA_CIPHER_* */
  int proactive_key_caching;
  int eap_workaround;
  void *eap_conf_ctx;
  const u8 *ssid;
  size_t ssid_len;
  int wpa_ptk_rekey;
};

#ifndef CONFIG_NO_WPA

struct wpa_sm * wpa_sm_init(struct wpa_sm_ctx *ctx);
void wpa_sm_deinit(struct wpa_sm *sm);
void wpa_sm_notify_assoc(struct wpa_sm *sm, const u8 *bssid);
void wpa_sm_notify_disassoc(struct wpa_sm *sm);
void wpa_sm_set_pmk(struct wpa_sm *sm, const u8 *pmk, size_t pmk_len);
void wpa_sm_set_pmk_from_pmksa(struct wpa_sm *sm);
void wpa_sm_set_fast_reauth(struct wpa_sm *sm, int fast_reauth);
void wpa_sm_set_scard_ctx(struct wpa_sm *sm, void *scard_ctx);
void wpa_sm_set_config(struct wpa_sm *sm, struct rsn_supp_config *config);
void wpa_sm_set_own_addr(struct wpa_sm *sm, const u8 *addr);
void wpa_sm_set_ifname(struct wpa_sm *sm, const char *ifname,
           const char *bridge_ifname);
void wpa_sm_set_eapol(struct wpa_sm *sm, struct eapol_sm *eapol);
int wpa_sm_set_assoc_wpa_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
int wpa_sm_set_assoc_wpa_ie_default(struct wpa_sm *sm, u8 *wpa_ie,
            size_t *wpa_ie_len);
int wpa_sm_set_ap_wpa_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
int wpa_sm_set_ap_rsn_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
int wpa_sm_get_mib(struct wpa_sm *sm, char *buf, size_t buflen);

int wpa_sm_set_param(struct wpa_sm *sm, enum wpa_sm_conf_params param,
         unsigned int value);
unsigned int wpa_sm_get_param(struct wpa_sm *sm,
            enum wpa_sm_conf_params param);

int wpa_sm_get_status(struct wpa_sm *sm, char *buf, size_t buflen,
          int verbose);

void wpa_sm_key_request(struct wpa_sm *sm, int error, int pairwise);

int wpa_parse_wpa_ie(const u8 *wpa_ie, size_t wpa_ie_len,
         struct wpa_ie_data *data);

void wpa_sm_aborted_cached(struct wpa_sm *sm);
int wpa_sm_rx_eapol(struct wpa_sm *sm, const u8 *src_addr,
        const u8 *buf, size_t len);
int wpa_sm_parse_own_wpa_ie(struct wpa_sm *sm, struct wpa_ie_data *data);

#else /* CONFIG_NO_WPA */

static inline struct wpa_sm * wpa_sm_init(struct wpa_sm_ctx *ctx)
{
  return (struct wpa_sm *) 1;
}

static inline void wpa_sm_deinit(struct wpa_sm *sm)
{
}

static inline void wpa_sm_notify_assoc(struct wpa_sm *sm, const u8 *bssid)
{
}

static inline void wpa_sm_notify_disassoc(struct wpa_sm *sm)
{
}

static inline void wpa_sm_set_pmk(struct wpa_sm *sm, const u8 *pmk,
          size_t pmk_len)
{
}

static inline void wpa_sm_set_pmk_from_pmksa(struct wpa_sm *sm)
{
}

static inline void wpa_sm_set_fast_reauth(struct wpa_sm *sm, int fast_reauth)
{
}

static inline void wpa_sm_set_scard_ctx(struct wpa_sm *sm, void *scard_ctx)
{
}

static inline void wpa_sm_set_config(struct wpa_sm *sm,
             struct rsn_supp_config *config)
{
}

static inline void wpa_sm_set_own_addr(struct wpa_sm *sm, const u8 *addr)
{
}

static inline void wpa_sm_set_ifname(struct wpa_sm *sm, const char *ifname,
             const char *bridge_ifname)
{
}

static inline void wpa_sm_set_eapol(struct wpa_sm *sm, struct eapol_sm *eapol)
{
}

static inline int wpa_sm_set_assoc_wpa_ie(struct wpa_sm *sm, const u8 *ie,
            size_t len)
{
  return -1;
}

static inline int wpa_sm_set_assoc_wpa_ie_default(struct wpa_sm *sm,
              u8 *wpa_ie,
              size_t *wpa_ie_len)
{
  return -1;
}

static inline int wpa_sm_set_ap_wpa_ie(struct wpa_sm *sm, const u8 *ie,
               size_t len)
{
  return -1;
}

static inline int wpa_sm_set_ap_rsn_ie(struct wpa_sm *sm, const u8 *ie,
               size_t len)
{
  return -1;
}

static inline int wpa_sm_get_mib(struct wpa_sm *sm, char *buf, size_t buflen)
{
  return 0;
}

static inline int wpa_sm_set_param(struct wpa_sm *sm,
           enum wpa_sm_conf_params param,
           unsigned int value)
{
  return -1;
}

static inline unsigned int wpa_sm_get_param(struct wpa_sm *sm,
              enum wpa_sm_conf_params param)
{
  return 0;
}

static inline int wpa_sm_get_status(struct wpa_sm *sm, char *buf,
            size_t buflen, int verbose)
{
  return 0;
}

static inline void wpa_sm_key_request(struct wpa_sm *sm, int error,
              int pairwise)
{
}

static inline int wpa_parse_wpa_ie(const u8 *wpa_ie, size_t wpa_ie_len,
           struct wpa_ie_data *data)
{
  return -1;
}

static inline void wpa_sm_aborted_cached(struct wpa_sm *sm)
{
}

static inline int wpa_sm_rx_eapol(struct wpa_sm *sm, const u8 *src_addr,
          const u8 *buf, size_t len)
{
  return -1;
}

static inline int wpa_sm_parse_own_wpa_ie(struct wpa_sm *sm,
            struct wpa_ie_data *data)
{
  return -1;
}

#endif /* CONFIG_NO_WPA */

#ifdef CONFIG_PEERKEY
int wpa_sm_stkstart(struct wpa_sm *sm, const u8 *peer);
#else /* CONFIG_PEERKEY */
static inline int wpa_sm_stkstart(struct wpa_sm *sm, const u8 *peer)
{
  return -1;
}
#endif /* CONFIG_PEERKEY */

#ifdef CONFIG_IEEE80211R

int wpa_sm_set_ft_params(struct wpa_sm *sm, const u8 *mobility_domain,
       const u8 *r0kh_id, size_t r0kh_id_len,
       const u8 *r1kh_id);
int wpa_ft_prepare_auth_request(struct wpa_sm *sm);
int wpa_ft_process_response(struct wpa_sm *sm, const u8 *ies, size_t ies_len,
          int ft_action, const u8 *target_ap);
int wpa_ft_is_completed(struct wpa_sm *sm);
int wpa_ft_validate_reassoc_resp(struct wpa_sm *sm, const u8 *ies,
         size_t ies_len, const u8 *src_addr);
int wpa_ft_start_over_ds(struct wpa_sm *sm, const u8 *target_ap);

#else /* CONFIG_IEEE80211R */

static inline int
wpa_sm_set_ft_params(struct wpa_sm *sm, const u8 *mobility_domain,
         const u8 *r0kh_id, const u8 *r1kh_id)
{
  return 0;
}

static inline int wpa_ft_prepare_auth_request(struct wpa_sm *sm)
{
  return 0;
}

static inline int
wpa_ft_process_response(struct wpa_sm *sm, const u8 *ies, size_t ies_len,
      int ft_action, const u8 *target_ap)
{
  return 0;
}

static inline int wpa_ft_is_completed(struct wpa_sm *sm)
{
  return 0;
}

static inline int
wpa_ft_validate_reassoc_resp(struct wpa_sm *sm, const u8 *ies, size_t ies_len,
           const u8 *src_addr)
{
  return -1;
}

#endif /* CONFIG_IEEE80211R */

#ifdef CONFIG_CCKM
int cckm_driver_newptk(struct wpa_sm *sm, u8 *bssid);
int wpa_supplicant_verify_cckm_key_mic(struct wpa_sm *sm,
                   uint rekey_number, u8  keyid, 
               u8  keyid_mcast, u8  *rsc, 
               u8 *gkey_len, u8 *mic, u8 *gtk,
               u8 *gd);
int wpa_install_cckm_newkeys(struct wpa_sm *sm, struct wpa_gtk_data *gtk);
void
wpa_cckm_hmac_calculate(struct wpa_sm *sm, u8 *wpa_ie, u8 wpa_ie_len, u8 *addr1, u8 *addr2, int rekey_number,
                        u8 *tsf, u8 *key, u8 key_len);
#endif
#endif /* WPA_H */
