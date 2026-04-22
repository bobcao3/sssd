/*
    SSSD

    IdP Identity Backend Module - evaluate replies

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <jansson.h>
#include <openssl/evp.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/idp/idp_id.h"

/**
 * Derive a deterministic UID from an email local part using SHA-256.
 * Parity with okta-sync-email.py email_to_uid().
 *
 * Algorithm:
 * 1. Lowercase email local part (strip @domain, strip +suffix)
 * 2. SHA-256 hash via OpenSSL EVP
 * 3. Byte-by-byte modular reduction to match Python int(digest,16) % range
 * 4. uid = min_uid + (reduced_val)
 *
 * Returns UID on success, 0 on error.
 */
static uid_t email_hash_to_uid(const char *email, uint32_t min_uid,
                                uint32_t max_uid)
{
    char local_part[256];
    const char *at;
    char *plus;
    size_t len;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = NULL;
    uint32_t range_size;
    uint32_t val = 0;

    if (email == NULL || min_uid > max_uid) return 0;

    /* Extract local part (before @) */
    at = strchr(email, '@');
    len = at ? (size_t)(at - email) : strlen(email);
    if (len == 0 || len >= sizeof(local_part)) return 0;
    memcpy(local_part, email, len);
    local_part[len] = '\0';

    /* Strip +suffix */
    plus = strchr(local_part, '+');
    if (plus) *plus = '\0';

    /* Lowercase */
    for (char *p = local_part; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') *p += 32;
    }

    /* SHA-256 via EVP */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, local_part, strlen(local_part)) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != 32) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_MD_CTX_free(ctx);

    /* Match Python: int(hexdigest, 16) % range_size
     * Process all 32 bytes with modular arithmetic so result
     * matches the full 256-bit integer mod exactly. */
    range_size = max_uid - min_uid + 1;
    for (int i = 0; i < 32; i++) {
        val = (uint32_t)(((uint64_t)val * 256 + digest[i]) % range_size);
    }

    return (uid_t)(min_uid + val);
}

/**
 * Check for UID/name collisions in sysdb before storing.
 * Returns EOK if safe, EEXIST if collision detected (skip this entry).
 */
static errno_t check_collision(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *dom,
                                const char *username, uid_t uid)
{
    errno_t ret;
    struct ldb_result *res = NULL;

    /* Check 1: existing user with same UID but different name */
    ret = sysdb_getpwuid(mem_ctx, dom, uid, &res);
    if (ret == EOK && res != NULL && res->count > 0) {
        const char *existing_name = ldb_msg_find_attr_as_string(
            res->msgs[0], SYSDB_NAME, NULL);
        if (existing_name != NULL &&
            strcmp(existing_name, username) != 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "UID COLLISION: uid %u already assigned to %s, "
                  "cannot assign to %s\n",
                  uid, existing_name, username);
            talloc_free(res);
            return EEXIST;
        }
    }
    talloc_free(res);
    res = NULL;

    /* Check 2: existing user with same name but different UID */
    ret = sysdb_getpwnam(mem_ctx, dom, username, &res);
    if (ret == EOK && res != NULL && res->count > 0) {
        uid_t existing_uid = (uid_t)ldb_msg_find_attr_as_uint64(
            res->msgs[0], SYSDB_UIDNUM, 0);
        if (existing_uid != 0 && existing_uid != uid) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "NAME COLLISION: %s already has uid %u, "
                  "cannot assign uid %u\n",
                  username, existing_uid, uid);
            talloc_free(res);
            return EEXIST;
        }
    }
    talloc_free(res);

    return EOK;
}

static errno_t store_json_user(struct idp_id_ctx *idp_id_ctx, json_t *user,
                               const char *group_name)
{
    errno_t ret;
    json_t *user_name = NULL;
    json_t *uuid = NULL;
    json_t *email_json = NULL;
    json_t *unix_user_name_json = NULL;
    json_t *email_user_name_json = NULL;
    int cache_timeout;
    struct sss_domain_info *dom;
    uid_t uid;
    gid_t gid;
    char *fqdn = NULL;
    char *email_fqdn = NULL;
    enum idmap_error_code err;
    struct sysdb_attrs *attrs = NULL;
    struct sysdb_attrs *email_attrs = NULL;
    bool email_uid_enabled;
    uint32_t email_uid_min, email_uid_max;
    const char *email = NULL;
    char *gecos = NULL;
    char *email_gecos = NULL;
    bool has_unix_username;
    bool has_email_username;

    dom = idp_id_ctx->be_ctx->domain;


    user_name = json_object_get(user, "posixUsername");
    if (!json_is_string(user_name)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON user object does not contain 'posixUsername' string.\n");
        ret = EINVAL;
        goto done;
    }

    fqdn = sss_create_internal_fqname(idp_id_ctx, json_string_value(user_name),
                                      dom->name);
    if (fqdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate fully-qualified name.\n");
        ret = ENOMEM;
        goto done;
    }

    uuid = json_object_get(user, "id");
    if (!json_is_string(uuid)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON user object does not contain 'id' string.\n");
        ret = EINVAL;
        goto done;
    }

    /* Read email (set by P3 enrichment) */
    email_json = json_object_get(user, "email");
    if (email_json != NULL && json_is_string(email_json)) {
        email = json_string_value(email_json);
    }

    /* Check if user has an explicit UnixUserName (legacy path) */
    unix_user_name_json = json_object_get(user, "UnixUserName");
    has_unix_username = (unix_user_name_json != NULL &&
                         json_is_string(unix_user_name_json) &&
                         json_string_value(unix_user_name_json)[0] != '\0');

    /* Check if an email-derived username was set by add_posix_to_json */
    email_user_name_json = json_object_get(user, "posixEmailUsername");
    has_email_username = (email_user_name_json != NULL &&
                          json_is_string(email_user_name_json) &&
                          json_string_value(email_user_name_json)[0] != '\0');

    /* For dual-account: email username must differ from posixUsername */
    if (has_unix_username && has_email_username &&
        strcmp(json_string_value(user_name),
               json_string_value(email_user_name_json)) == 0) {
        has_email_username = false;
    }

    /* Read email-UID config options */
    email_uid_enabled = dp_opt_get_bool(idp_id_ctx->idp_options,
                                         IDP_EMAIL_UID_ENABLED);
    email_uid_min = (uint32_t)dp_opt_get_int(idp_id_ctx->idp_options,
                                              IDP_EMAIL_UID_MIN);
    email_uid_max = (uint32_t)dp_opt_get_int(idp_id_ctx->idp_options,
                                              IDP_EMAIL_UID_MAX);

    if (has_unix_username) {
        /* Legacy path: UID via idmap hash (unchanged) */
        err = sss_idmap_gen_to_unix(idp_id_ctx->idmap_ctx,
                                    idp_id_ctx->token_endpoint,
                                    json_string_value(uuid), &uid);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to generate UID for [%s][%s].\n",
                                     fqdn, json_string_value(uuid));
            ret = EIO;
            goto done;
        }
        gecos = talloc_asprintf(idp_id_ctx, "OktaManaged-%s",
                                json_string_value(uuid));
        if (gecos == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate GECOS string.\n");
            ret = ENOMEM;
            goto done;
        }
    } else if (email != NULL && email_uid_enabled) {
        /* Email-only path: UID via SHA-256 hash */
        uid = email_hash_to_uid(email, email_uid_min, email_uid_max);
        if (uid == 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to generate email-hash UID for [%s].\n", fqdn);
            ret = EIO;
            goto done;
        }
        gecos = talloc_asprintf(idp_id_ctx, "EmailSyncManaged-%s",
                                json_string_value(uuid));
        if (gecos == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate GECOS string.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        /* No UnixUserName AND no email / email_uid disabled */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "User [%s] has no UnixUserName and no email, skipping.\n",
              fqdn);
        ret = EINVAL;
        goto done;
    }

    if (dom->mpg_mode != MPG_DISABLED) {
        gid = 0;
    } else {
        gid = uid;
    }

    /* Collision detection */
    ret = check_collision(idp_id_ctx, dom, json_string_value(user_name), uid);
    if (ret == EEXIST) {
        /* Skip this user (parity with okta-sync-email.py) */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Collision detected for user [%s] uid %u, skipping.\n",
              fqdn, uid);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    attrs = sysdb_new_attrs(idp_id_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allocate memory for extra attributes.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_UUID, json_string_value(uuid));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add UUID to user attributes.\n");
        goto done;
    }

    /* Store email if available */
    if (email != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_USER_EMAIL, email);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add email to user attributes.\n");
            goto done;
        }
    }

    cache_timeout = dom->user_timeout;
    ret = sysdb_store_user(dom, fqdn, NULL,
                           uid, gid, gecos, NULL, NULL, NULL, attrs, NULL,
                           cache_timeout, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to store user [%s].\n", fqdn);
        goto done;
    }

    if (group_name != NULL) {
        ret = sysdb_add_group_member(dom, group_name, fqdn, SYSDB_MEMBER_USER,
                                     false);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to store user [%s] as member of group [%s].\n",
                      fqdn, group_name);
                goto done;
            }
    }

    /* Dual-account: if posixEmailUsername differs from posixUsername,
     * store a second sysdb entry with email-hash UID and EmailSyncManaged GECOS. */
    if (has_unix_username && has_email_username
            && email != NULL && email_uid_enabled) {
        uid_t email_uid;
        gid_t email_gid;

        email_uid = email_hash_to_uid(email, email_uid_min, email_uid_max);
        if (email_uid == 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to compute email-hash UID for dual-account [%s]; "
                  "skipping email entry.\n",
                  json_string_value(email_user_name_json));
            ret = EOK;
            goto done;
        }

        email_fqdn = sss_create_internal_fqname(
                         idp_id_ctx,
                         json_string_value(email_user_name_json),
                         dom->name);
        if (email_fqdn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to generate fqdn for email account.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = check_collision(idp_id_ctx, dom,
                              json_string_value(email_user_name_json),
                              email_uid);
        if (ret == EEXIST) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Collision for email account [%s] uid %u, skipping.\n",
                  email_fqdn, email_uid);
            ret = EOK;
            goto done;
        } else if (ret != EOK) {
            goto done;
        }

        email_gecos = talloc_asprintf(idp_id_ctx, "EmailSyncManaged-%s",
                                      json_string_value(uuid));
        if (email_gecos == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to allocate GECOS for email account.\n");
            ret = ENOMEM;
            goto done;
        }

        email_gid = (dom->mpg_mode != MPG_DISABLED) ? 0 : email_uid;

        email_attrs = sysdb_new_attrs(idp_id_ctx);
        if (email_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to allocate attrs for email account.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_add_string(email_attrs, SYSDB_UUID,
                                     json_string_value(uuid));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add UUID to email account attrs.\n");
            goto done;
        }

        ret = sysdb_attrs_add_string(email_attrs, SYSDB_USER_EMAIL, email);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add email to email account attrs.\n");
            goto done;
        }

        cache_timeout = dom->user_timeout;
        ret = sysdb_store_user(dom, email_fqdn, NULL,
                               email_uid, email_gid, email_gecos,
                               NULL, NULL, NULL, email_attrs, NULL,
                               cache_timeout, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store email account [%s].\n", email_fqdn);
            goto done;
        }

        if (group_name != NULL) {
            ret = sysdb_add_group_member(dom, group_name, email_fqdn,
                                         SYSDB_MEMBER_USER, false);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to add email account [%s] to group [%s].\n",
                      email_fqdn, group_name);
                goto done;
            }
        }

        DEBUG(SSSDBG_TRACE_LIBS,
              "Stored dual-account email entry [%s] uid=%u.\n",
              email_fqdn, email_uid);
    }

done:
    talloc_free(attrs);
    talloc_free(email_attrs);
    talloc_free(fqdn);
    talloc_free(email_fqdn);
    talloc_free(gecos);
    talloc_free(email_gecos);

    return ret;
}

static errno_t del_user(struct idp_id_ctx *idp_id_ctx, const char *user_name)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Trying to delete user [%s].\n", user_name);
    return sysdb_delete_user(idp_id_ctx->be_ctx->domain, user_name, 0);
}

static errno_t store_json_group(struct idp_id_ctx *idp_id_ctx, json_t *group,
                                const char *user_name)
{
    errno_t ret;
    json_t *group_name = NULL;
    json_t *uuid = NULL;
    struct sss_domain_info *dom;
    gid_t gid;
    char *fqdn = NULL;
    enum idmap_error_code err;
    struct sysdb_attrs *attrs = NULL;

    dom = idp_id_ctx->be_ctx->domain;


    group_name = json_object_get(group, "posixGroupname");
    if (!json_is_string(group_name)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON group object does not contain 'posixGroupname' string.\n");
        ret = EINVAL;
        goto done;
    }

    fqdn = sss_create_internal_fqname(idp_id_ctx, json_string_value(group_name),
                                      dom->name);
    if (fqdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate fully-qualified name.\n");
        ret = ENOMEM;
        goto done;
    }

    uuid = json_object_get(group, "id");
    if (!json_is_string(uuid)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON group object does not contain 'id' string.\n");
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_gen_to_unix(idp_id_ctx->idmap_ctx,
                                idp_id_ctx->token_endpoint,
                                json_string_value(uuid), &gid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate GID for [%s][%s].\n",
                                 fqdn, json_string_value(uuid));
        ret = EIO;
        goto done;
    }

    attrs = sysdb_new_attrs(idp_id_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allocate memory for extra attributes.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_UUID, json_string_value(uuid));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add UUID to group attributes.\n");
        goto done;
    }

    /* If we just add a single member to a group (user_name != NULL) we do not
     * want to change the cache timeout. Calling `sysdb_add_incomplete_group()
     * will check if the group already exists (ret == ERR_GID_DUPLICATED) or
     * create an expired group object (ret == EOK). In both cases there will
     * be a cached group object where the user can be added as a member. */
    if (user_name == NULL) {
        ret = sysdb_store_group(dom, fqdn, gid, attrs, dom->group_timeout, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store group [%s].\n", fqdn);
            goto done;
        }
    } else {
        ret = sysdb_add_incomplete_group(dom, fqdn, gid, NULL, NULL,
                                         json_string_value(uuid),
                                         gid != 0, 0);
        if (ret != EOK && ret != ERR_GID_DUPLICATED) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to create incomplete group [%s].\n", fqdn);
            goto done;
        }

        ret = sysdb_add_group_member(dom, fqdn, user_name, SYSDB_MEMBER_USER,
                                     false);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store user [%s] as member of group [%s].\n",
                  user_name, fqdn);
            goto done;
        }
    }

done:
    talloc_free(attrs);
    talloc_free(fqdn);

    return ret;
}

static errno_t del_group(struct idp_id_ctx *idp_id_ctx, const char *group_name)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Trying to delete group [%s].\n", group_name);
    return sysdb_delete_group(idp_id_ctx->be_ctx->domain, group_name, 0);
}

typedef errno_t (store_func_t)(struct idp_id_ctx *idp_id_ctx, json_t *obj,
                               const char *name);

typedef errno_t (del_func_t)(struct idp_id_ctx *idp_id_ctx, const char *name);

static errno_t eval_obj_buf(struct idp_id_ctx *idp_id_ctx,
                            const char *type, store_func_t *store_func,
                            del_func_t *del_func, const char *name,
                            const char *del_obj_name, bool noexist_delete,
                            const uint8_t *buf, ssize_t buflen)
{
    errno_t ret;
    json_t *data = NULL;
    json_error_t json_error;
    char *tmp = NULL;
    size_t index;
    json_t *obj;

    data = json_loadb((const char *) buf, buflen, 0, &json_error);
    if (data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse %s data on line [%d]: [%s].\n",
              type, json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    if (!json_is_array(data)) {
        DEBUG(SSSDBG_OP_FAILURE, "Array of %ss expected.\n", type);
        ret = EINVAL;
        goto done;
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        tmp = json_dumps(data, 0);
        if (tmp != NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "JSON: %s\n", tmp);
            free(tmp);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "json_dumps() failed.\n");
        }
    }

    if (json_array_size(data) == 0 && noexist_delete) {
        ret = del_func(idp_id_ctx, del_obj_name);
        if (ret == ENOENT) {
            ret = EOK;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to delete %s [%s].\n",
                                     type, del_obj_name);
        }
        goto done;
    }

    json_array_foreach(data, index, obj) {
        ret = store_func(idp_id_ctx, obj, name);
        if (ret != EOK) {
            tmp = json_dumps(obj, 0);
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store JSON %s [%s].\n", type,
                                                                         tmp);
            free(tmp);
        }
    }

    ret = EOK;
done:
    json_decref(data);

    return ret;
}

errno_t eval_user_buf(struct idp_id_ctx *idp_id_ctx,
                      const char *group_name,
                      const char *del_name,
                      bool noexist_delete,
                      uint8_t *buf, ssize_t buflen)
{
    return eval_obj_buf(idp_id_ctx, "user", store_json_user, del_user,
                        group_name, del_name, noexist_delete, buf, buflen);
}

errno_t eval_group_buf(struct idp_id_ctx *idp_id_ctx,
                       const char *user_name,
                       const char *del_name,
                       bool noexist_delete,
                       uint8_t *buf, ssize_t buflen)
{
    return eval_obj_buf(idp_id_ctx, "group", store_json_group, del_group,
                        user_name, del_name, noexist_delete, buf, buflen);
}
