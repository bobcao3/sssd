/*
    SSSD

    Helper child for reading user and group information form IdPs

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

#include "oidc_child/oidc_child_util.h"

#include "util/util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#define IS_ID_CMD(cmd) ( \
    cmd == GET_USER || cmd == GET_USER_GROUPS \
                              || cmd == GET_GROUP \
                              || cmd == GET_GROUP_MEMBERS )

/* ---- Token cache --------------------------------------------------------
 *
 * Each oidc_child invocation is a fresh fork+exec from sssd_be, so no
 * in-process state survives. Cache lives in tmpfs at /run/sssd, keyed on
 * sha256(client_id|token_endpoint|scope), so independent IdP configs do
 * not share entries. Reads take a shared flock; writes go through a
 * per-pid temp file + atomic rename. A successful write races between
 * concurrent forks are benign — last-writer-wins, both tokens are
 * independently valid until expiry.
 */
#define TOKEN_CACHE_DIR            "/run/sssd"
#define TOKEN_CACHE_SKEW_S         60
#define TOKEN_CACHE_DEFAULT_TTL_S  3600

static char *token_cache_path(TALLOC_CTX *mem_ctx,
                              const char *client_id,
                              const char *token_endpoint,
                              const char *scope)
{
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    char hex[2 * 32 + 1];
    char *path = NULL;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) goto done;
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) goto done;
    EVP_DigestUpdate(md_ctx, client_id, strlen(client_id));
    EVP_DigestUpdate(md_ctx, "|", 1);
    EVP_DigestUpdate(md_ctx, token_endpoint, strlen(token_endpoint));
    EVP_DigestUpdate(md_ctx, "|", 1);
    if (scope != NULL) {
        EVP_DigestUpdate(md_ctx, scope, strlen(scope));
    }
    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1) goto done;
    if (digest_len < 32) goto done;

    for (unsigned i = 0; i < 32; i++) {
        snprintf(&hex[i * 2], 3, "%02x", digest[i]);
    }
    hex[64] = '\0';
    path = talloc_asprintf(mem_ctx, "%s/oidc_token_%s.json",
                           TOKEN_CACHE_DIR, hex);

done:
    EVP_MD_CTX_free(md_ctx);
    return path;
}

/* EOK: hit, *out_token populated.
 * ENOENT: miss.
 * ETIMEDOUT: present but within skew of expiry.
 * other: I/O / parse error. */
static errno_t token_cache_read(TALLOC_CTX *mem_ctx, const char *path,
                                const char **out_token)
{
    int fd = -1;
    char buf[4096];
    ssize_t n;
    json_t *obj = NULL;
    json_t *exp_j;
    json_t *tok_j;
    json_error_t je;
    errno_t ret = EIO;

    *out_token = NULL;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        ret = (errno == ENOENT) ? ENOENT : errno;
        goto done;
    }
    if (flock(fd, LOCK_SH) != 0) {
        ret = errno;
        goto done;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        ret = ENOENT;
        goto done;
    }
    buf[n] = '\0';

    obj = json_loads(buf, 0, &je);
    if (obj == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Token cache parse failed at line %d: %s.\n",
              je.line, je.text);
        ret = EINVAL;
        goto done;
    }
    exp_j = json_object_get(obj, "exp");
    tok_j = json_object_get(obj, "access_token");
    if (!json_is_integer(exp_j) || !json_is_string(tok_j)) {
        ret = EINVAL;
        goto done;
    }
    if ((time_t)json_integer_value(exp_j) - time(NULL) < TOKEN_CACHE_SKEW_S) {
        ret = ETIMEDOUT;
        goto done;
    }
    *out_token = talloc_strdup(mem_ctx, json_string_value(tok_j));
    ret = (*out_token != NULL) ? EOK : ENOMEM;

done:
    if (obj != NULL) json_decref(obj);
    if (fd >= 0) close(fd);
    return ret;
}

/* Best-effort: never fails the caller. */
static void token_cache_write(const char *path,
                              const char *access_token,
                              long expires_in)
{
    char *tmp = NULL;
    int fd = -1;
    json_t *obj = NULL;
    char *body = NULL;
    time_t exp_at;

    if (path == NULL || access_token == NULL) return;

    if (expires_in <= 2 * TOKEN_CACHE_SKEW_S) {
        expires_in = TOKEN_CACHE_DEFAULT_TTL_S;
    }
    exp_at = time(NULL) + expires_in - TOKEN_CACHE_SKEW_S;

    if (mkdir(TOKEN_CACHE_DIR, 0700) != 0 && errno != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Token cache mkdir [%s] failed: %s.\n",
              TOKEN_CACHE_DIR, strerror(errno));
        return;
    }

    if (asprintf(&tmp, "%s.tmp.%d", path, (int)getpid()) < 0) {
        return;
    }

    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Token cache open [%s] failed: %s.\n", tmp, strerror(errno));
        goto done;
    }

    obj = json_object();
    if (obj == NULL) goto done;
    if (json_object_set_new(obj, "access_token",
                            json_string(access_token)) != 0) goto done;
    if (json_object_set_new(obj, "exp",
                            json_integer((json_int_t)exp_at)) != 0) goto done;
    body = json_dumps(obj, JSON_COMPACT);
    if (body == NULL) goto done;

    {
        size_t left = strlen(body);
        const char *p = body;
        while (left > 0) {
            ssize_t w = write(fd, p, left);
            if (w < 0) {
                if (errno == EINTR) continue;
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Token cache write failed: %s.\n", strerror(errno));
                goto done;
            }
            p += w;
            left -= (size_t)w;
        }
    }

    if (close(fd) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Token cache close failed: %s.\n", strerror(errno));
    }
    fd = -1;

    if (rename(tmp, path) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Token cache rename [%s -> %s] failed: %s.\n",
              tmp, path, strerror(errno));
        unlink(tmp);
    }

done:
    if (fd >= 0) close(fd);
    if (obj != NULL) json_decref(obj);
    free(body);
    free(tmp);
}

static long parse_expires_in(const char *json_str)
{
    json_t *obj;
    json_t *exp_j;
    json_error_t je;
    long ttl = TOKEN_CACHE_DEFAULT_TTL_S;

    if (json_str == NULL) return ttl;
    obj = json_loads(json_str, 0, &je);
    if (obj == NULL) return ttl;
    exp_j = json_object_get(obj, "expires_in");
    if (json_is_integer(exp_j)) ttl = (long)json_integer_value(exp_j);
    json_decref(obj);
    return ttl;
}

/* Extracts and normalizes the base URL from an idp_type string of
 * the form https://... Sets *base_url to NULL if no URL is present
 *
 * Entra will use default microsoft url if not present, while keycloak
 * will fail. */
static errno_t parse_base_url_from_idp_type(TALLOC_CTX *mem_ctx,
                                            const char *idp_type,
                                            char **_base_url)
{
    char *base_url;
    char *last;
    const char *colon;
    char *p;
    char *limit;

    if (idp_type == NULL) {
        *_base_url = NULL;
        return EOK;
    }

    colon = strchr(idp_type, ':');
    if (colon == NULL) {
        *_base_url = NULL;
        return EOK;
    }

    base_url = talloc_strdup(mem_ctx, colon + 1);
    if (base_url == NULL) {
        return ENOMEM;
    }

    if (*base_url == '\0' || strncasecmp(base_url, "http", 4) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Colon supplied in [%s] but no valid URL found.\n", idp_type);
        talloc_free(base_url);
        return EINVAL;
    }

    /* strip trailing slashes if it is not part of scheme */
    p = strstr(base_url, "://");
    limit = p ? p + 2 : base_url;
    last = base_url + strlen(base_url) - 1;
    while (last > limit && *last == '/') last--;
    last[1] = '\0';

    *_base_url = base_url;
    return EOK;
}

/* The following function will lookup users and groups based on Mircosoft's
 * Graph API as described in
 * https://learn.microsoft.com/de-de/graph/api/overview */
errno_t entra_id_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                        char *base_url,
                        char *input, enum search_str_type input_type,
                        bool libcurl_debug, const char *ca_db,
                        const char *client_id, const char *client_secret,
                        const char *token_endpoint, const char *scope,
                        const char *bearer_token, struct rest_ctx *rest_ctx,
                        char **out)
{
    errno_t ret;
    char *uri;
    char *filter;
    char *filter_enc;
    const char *obj_id;
    const char **id_list;
    char *short_name;
    char *sep;
    char *tmp;
    struct name_and_type_identifier entra_name_and_type_identifier = {
                            .user_identifier_attr = "userPrincipalName",
                            .group_identifier_attr = "groupTypes",
                            .user_name_attr = "userPrincipalName",
                            .group_name_attr = "displayName" };

    if (base_url == NULL) {
        base_url = talloc_strdup(mem_ctx, "https://graph.microsoft.com/v1.0");
        if (base_url == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            filter = talloc_asprintf(rest_ctx, "startsWith(userPrincipalName,'%s@')", input);
        } else {
            filter = talloc_asprintf(rest_ctx,
                                     "mail eq '%s' or userPrincipalName eq '%s'",
                                     input, input);
        }
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            filter = talloc_asprintf(rest_ctx, "displayName eq '%s'", input);
        } else {
            short_name = talloc_strndup(rest_ctx, input, sep - input);
            if (short_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to generate short name, using plain input [%s].\n",
                      input);
                filter = talloc_asprintf(rest_ctx, "displayName eq '%s'", input);
            } else {
                filter = talloc_asprintf(rest_ctx,
                                         "displayName eq '%s' or displayName eq '%s'",
                                         input, short_name);
            }
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    filter_enc = url_encode_string(rest_ctx, filter);
    if (filter_enc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to encode user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/users?$filter=%s", base_url, filter_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/groups?$filter=%s", base_url, filter_enc);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "User search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        ret = EOK;
        goto done;
    }

    obj_id = get_str_attr_from_embed_json_string(rest_ctx,
                                                 get_http_data(rest_ctx),
                                                 "value", "id");
    if (obj_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read mandatory object id.\n");
        ret = EINVAL;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/users/%s/getMemberGroups",
                              base_url, obj_id);
        break;
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/groups/%s/members",
                              base_url, obj_id);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        ret = do_http_request_json_data(rest_ctx, uri, "{\"securityEnabledOnly\": true}", bearer_token);
        break;
    case GET_GROUP_MEMBERS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Member(of) search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_GROUP_MEMBERS) {
        goto done;
    }

    id_list = get_str_list_from_json_string(rest_ctx, get_http_data(rest_ctx),
                                            "value");
    if (id_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get id list.\n");
        ret = EINVAL;
        goto done;
    }

    if (out != NULL) {
        *out = get_json_string_array_by_id_list(mem_ctx, rest_ctx, bearer_token,
                                                id_list);
        if (*out == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get objects by ID.\n");
            ret = EIO;
            goto done;
        }
    }

done:
    if (ret == EOK && out != NULL && oidc_cmd != GET_USER_GROUPS) {
        *out = get_json_string_array_from_json_string(mem_ctx, get_http_data(rest_ctx), "value");
        if (*out == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy output data.\n");
            ret = ENOMEM;
        }
    }

    if (ret == EOK && out != NULL) {
        ret = add_posix_to_json_string_array(mem_ctx,
                                             &entra_name_and_type_identifier,
                                             '@', *out, &tmp);
        talloc_free(*out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add POSIX data.\n");
            *out = NULL;
        } else {
            *out = tmp;
        }
    }

    return ret;
}

/* Flatten Okta's nested profile object to top level for each item in the
 * JSON array. Okta returns user/group attributes under a "profile" sub-object;
 * this extracts them to the top level so that existing JSON helpers can access
 * attributes like "login" and "name" directly. */
static char *okta_flatten_profile_array(TALLOC_CTX *mem_ctx,
                                        const char *json_in)
{
    json_error_t json_error;
    json_t *array = NULL;
    json_t *item;
    json_t *profile;
    size_t index;
    const char *key;
    json_t *val;
    char *tmp;
    char *out = NULL;

    array = json_loads(json_in, 0, &json_error);
    if (array == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse json data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        return NULL;
    }

    if (!json_is_array(array)) {
        DEBUG(SSSDBG_OP_FAILURE, "Input is not a JSON array.\n");
        goto done;
    }

    json_array_foreach(array, index, item) {
        if (!json_is_object(item)) {
            continue;
        }

        profile = json_object_get(item, "profile");
        if (!json_is_object(profile)) {
            continue;
        }

        json_object_foreach(profile, key, val) {
            /* Only promote if the key is not already at the top level,
             * to avoid overwriting reserved fields like "id". */
            if (json_object_get(item, key) == NULL) {
                json_object_set(item, key, val);
            }
        }
    }

    tmp = json_dumps(array, 0);
    if (tmp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_dumps() failed.\n");
        goto done;
    }

    out = talloc_strdup(mem_ctx, tmp);
    free(tmp);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup() failed.\n");
    }

done:
    json_decref(array);
    return out;
}

/* The following function will lookup users and groups based on Okta's
 * REST API as described in
 * https://developer.okta.com/docs/reference/api/users/ and
 * https://developer.okta.com/docs/reference/api/groups/ */
errno_t okta_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                    char *base_url,
                    char *input, enum search_str_type input_type,
                    bool libcurl_debug, const char *ca_db,
                    const char *client_id, const char *client_secret,
                    const char *token_endpoint, const char *scope,
                    const char *bearer_token, struct rest_ctx *rest_ctx,
                    char **out)
{
    errno_t ret;
    char *uri;
    char *search_expr = NULL;
    char *search_enc;
    char *short_name;
    char *sep;
    const char *obj_id;
    char *flat;
    bool found = false;
    /* Search strategies: for short-name user queries we try UnixUserName
     * first, then fall back to login starts-with for email-only users. */
    const char *search_strategies[2];
    int n_strategies = 0;
    int strategy;
    struct name_and_type_identifier okta_name_and_type_identifier = {
                            .user_identifier_attr = "login",
                            .group_identifier_attr = "name",
                            .user_name_attr = "UnixUserName",
                            .group_name_attr = "name",
                            .user_email_attr = "email",
                            .user_name_fallback_attr = "email" };

    if (base_url == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing base URL in IdP type [okta].\n");
        return EINVAL;
    }

    /* Build search expression(s) based on command and input type */
    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            /* Short name: try UnixUserName first, then login starts-with */
            search_strategies[n_strategies++] =
                talloc_asprintf(rest_ctx,
                                "profile.UnixUserName eq \"%s\"", input);
            search_strategies[n_strategies++] =
                talloc_asprintf(rest_ctx,
                                "profile.login sw \"%s@\"", input);
        } else {
            /* Full login: exact match (single strategy) */
            search_strategies[n_strategies++] =
                talloc_asprintf(rest_ctx,
                                "profile.login eq \"%s\"", input);
        }
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            search_strategies[n_strategies++] =
                talloc_asprintf(rest_ctx,
                                "profile.name eq \"%s\"", input);
        } else {
            short_name = talloc_strndup(rest_ctx, input, sep - input);
            if (short_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to generate short name, using plain input [%s].\n",
                      input);
                search_strategies[n_strategies++] =
                    talloc_asprintf(rest_ctx,
                                    "profile.name eq \"%s\"", input);
            } else {
                search_strategies[n_strategies++] =
                    talloc_asprintf(rest_ctx,
                                    "profile.name eq \"%s\" or "
                                    "profile.name eq \"%s\"",
                                    input, short_name);
            }
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    for (strategy = 0; strategy < n_strategies; strategy++) {
        if (search_strategies[strategy] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to create search expression.\n");
            ret = ENOMEM;
            goto done;
        }

        search_enc = url_encode_string(rest_ctx, search_strategies[strategy]);
        if (search_enc == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to encode search expression.\n");
            ret = ENOMEM;
            goto done;
        }

        switch (oidc_cmd) {
        case GET_USER:
        case GET_USER_GROUPS:
            uri = talloc_asprintf(rest_ctx, "%s/api/v1/users?search=%s",
                                  base_url, search_enc);
            break;
        case GET_GROUP:
        case GET_GROUP_MEMBERS:
            uri = talloc_asprintf(rest_ctx, "%s/api/v1/groups?search=%s",
                                  base_url, search_enc);
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
            ret = EINVAL;
            goto done;
        }

        if (uri == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
            ret = ENOMEM;
            goto done;
        }

        clean_http_data(rest_ctx);
        ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
        talloc_free(uri);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Search request failed.\n");
            goto done;
        }

        /* Check if response has results */
        const char *http_data = get_http_data(rest_ctx);
        json_error_t json_error;
        json_t *resp = json_loads(http_data, 0, &json_error);
        if (resp != NULL && json_is_array(resp) && json_array_size(resp) > 0) {
            json_decref(resp);
            found = true;
            break;
        }
        json_decref(resp);

        /* No results: if more strategies, try next (email fallback) */
        DEBUG(SSSDBG_TRACE_LIBS,
              "Search strategy %d returned no results for [%s].\n",
              strategy, input);
    }

    if (!found) {
        DEBUG(SSSDBG_OP_FAILURE,
              "No results found for [%s] after all search strategies.\n", input);
        ret = ENOENT;
        goto done;
    }

    if (oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        ret = EOK;
        goto done;
    }

    obj_id = get_str_attr_from_json_array_string(rest_ctx,
                                                 get_http_data(rest_ctx),
                                                 "id");
    if (obj_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read mandatory object id.\n");
        ret = EINVAL;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/api/v1/users/%s/groups",
                              base_url, obj_id);
        break;
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/api/v1/groups/%s/users",
                              base_url, obj_id);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Member(of) search request failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK && out != NULL) {
        flat = okta_flatten_profile_array(mem_ctx, get_http_data(rest_ctx));
        if (flat == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to flatten Okta profile data.\n");
            ret = EIO;
        } else {
            ret = add_posix_to_json_string_array(mem_ctx,
                                                 &okta_name_and_type_identifier,
                                                 '@', flat, out);
            talloc_free(flat);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to add POSIX data.\n");
            }
        }
    }

    return ret;
}

/* The following function will lookup users and groups based on Keycloak's
 * REST API as described in
 * https://www.keycloak.org/docs-api/latest/rest-api/index.html */
errno_t keycloak_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                        char *base_url,
                        char *input, enum search_str_type input_type,
                        bool libcurl_debug, const char *ca_db,
                        const char *client_id, const char *client_secret,
                        const char *token_endpoint, const char *scope,
                        const char *bearer_token, struct rest_ctx *rest_ctx,
                        char **out)
{
    errno_t ret;
    char *uri;
    char *filter;
    char *filter_enc;
    char *input_enc;
    const char *obj_id;
    char *short_name;
    char *sep;
    struct name_and_type_identifier keycloak_name_and_type_identifier = {
                            .user_identifier_attr = "username",
                            .group_identifier_attr = "name",
                            .user_name_attr = "username",
                            .group_name_attr = "name" };

    if (base_url == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing base URL in IdP type [keycloak].\n");
        return EINVAL;
    }

    input_enc = url_encode_string(rest_ctx, input);
    if (input_enc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to encode input [%s].\n", input);
        return EINVAL;
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        filter = talloc_asprintf(rest_ctx, "username=%s&exact=true", input_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        sep = strrchr(input, '@');
        if (sep == NULL && sep != input) {
            filter = talloc_asprintf(rest_ctx, "search=%s&exact=true&populateHierarchy=false&briefRepresentation=false", input_enc);
        } else {
            short_name = talloc_strndup(rest_ctx, input, sep - input);
            if (short_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to generate short name, using plain input [%s].\n",
                      input);
                filter = talloc_asprintf(rest_ctx, "search=%s&exact=true",
                                                   input_enc);
            } else {
                filter = talloc_asprintf(rest_ctx, "search=%s&exact=true",
                                                   short_name);
            }
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    filter_enc = filter;

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/users?%s", base_url, filter_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/groups?%s", base_url, filter_enc);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "User search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        ret = EOK;
        goto done;
    }

    obj_id = get_str_attr_from_json_array_string(rest_ctx, get_http_data(rest_ctx),
                                                 "id");
    if (obj_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read mandatory object id.\n");
        ret = EINVAL;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx,
                              "%s/users/%s/groups?briefRepresentation=false", base_url, obj_id);
        break;
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx,
                              "%s/groups/%s/members", base_url, obj_id);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    case GET_GROUP_MEMBERS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Member(of) search request failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK && out != NULL) {
        ret = add_posix_to_json_string_array(mem_ctx,
                                             &keycloak_name_and_type_identifier,
                                             0, get_http_data(rest_ctx), out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add POSIX data.\n");
        }
    }

    return ret;
}

errno_t oidc_get_id(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                    char *idp_type,
                    char *input, enum search_str_type input_type,
                    bool libcurl_debug, const char *ca_db,
                    const char *client_id, const char *client_secret,
                    const char *private_key_file, const char *private_key_kid,
                    const char *token_endpoint, const char *scope,
                    bool no_token_cache, char **out)
{
    errno_t ret;
    struct rest_ctx *rest_ctx;
    char *cli_cred_reply;
    const char *bearer_token;
    char *cache_path = NULL;
    bool used_cached = false;
    bool retried = false;

    if (!IS_ID_CMD(oidc_cmd)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported command [%d].\n", oidc_cmd);
        return EINVAL;
    }

    if (client_id == NULL || token_endpoint == NULL || input == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing required argument.\n");
        return EINVAL;
    }

    if (client_secret == NULL && private_key_file == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "One of client_secret or private_key_file must be provided.\n");
        return EINVAL;
    }

    rest_ctx = get_rest_ctx(mem_ctx, libcurl_debug, ca_db);
    if (rest_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get REST context.\n");
        return ENOMEM;
    }

    /* Try the on-disk token cache first (unless explicitly disabled).
     * Survives across oidc_child forks because each new process re-reads
     * the file. Miss / stale falls through to a fresh client_credentials
     * grant; on success we write the new token back for the next fork to
     * reuse. If a cached token is later rejected with HTTP 401 by the
     * lookup endpoint, we invalidate the cache and retry once with a
     * freshly minted token (see retry_with_fresh_token below). */
    if (!no_token_cache) {
        cache_path = token_cache_path(mem_ctx, client_id,
                                      token_endpoint, scope);
    }

acquire_token:
    {
        const char *cached_token = NULL;
        errno_t cret;

        if (cache_path != NULL && !retried) {
            cret = token_cache_read(mem_ctx, cache_path, &cached_token);
            if (cret == EOK && cached_token != NULL) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Reusing cached access_token for client_id=[%s].\n",
                      client_id);
                bearer_token = cached_token;
                used_cached = true;
                goto have_token;
            }
            if (cret != ENOENT && cret != ETIMEDOUT) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Token cache read failed: %d (%s).\n",
                      cret, strerror(cret));
            }
        }

        used_cached = false;
        if (private_key_file != NULL) {
            ret = client_credentials_grant_jwt(rest_ctx, token_endpoint,
                                               client_id, private_key_file,
                                               private_key_kid, scope);
        } else {
            ret = client_credentials_grant(rest_ctx, token_endpoint,
                                           client_id, client_secret, scope);
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to get access token with client credentials grant.\n");
            goto done;
        }

        cli_cred_reply = talloc_strdup(rest_ctx, get_http_data(rest_ctx));
        bearer_token = get_bearer_token(rest_ctx, cli_cred_reply);

        if (cache_path != NULL && bearer_token != NULL) {
            token_cache_write(cache_path, bearer_token,
                              parse_expires_in(cli_cred_reply));
        }
    }
have_token:

    if (input_type ==TYPE_OBJECT_ID) {
        ret = ENOTSUP;
        goto done;
    }

    char *base_url = NULL;

    ret = parse_base_url_from_idp_type(mem_ctx, idp_type, &base_url);
    if (ret != EOK) {
        goto done;
    }

    if (idp_type != NULL && strncasecmp(idp_type, "keycloak:",9) == 0) {
        ret = keycloak_lookup(mem_ctx, oidc_cmd, base_url, input, input_type,
                              libcurl_debug, ca_db, client_id, client_secret,
                              token_endpoint, scope, bearer_token, rest_ctx,
                              out);
    } else if (idp_type != NULL && strncasecmp(idp_type, "okta:", 5) == 0) {
        ret = okta_lookup(mem_ctx, oidc_cmd, base_url, input, input_type,
                          libcurl_debug, ca_db, client_id, client_secret,
                          token_endpoint, scope, bearer_token, rest_ctx,
                          out);
    } else if (idp_type == NULL
               || strcasecmp(idp_type, "entra_id") == 0
               || strncasecmp(idp_type, "entra_id:", 9) == 0) {
        ret = entra_id_lookup(mem_ctx, oidc_cmd, base_url, input, input_type,
                              libcurl_debug, ca_db, client_id, client_secret,
                              token_endpoint, scope, bearer_token, rest_ctx,
                              out);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported IdP type [%s].\n", idp_type);
        ret = EINVAL;
        goto done;
    }

    /* If a *cached* token was rejected (HTTP 401 from the IdP),
     * invalidate the cache file and retry the lookup ONCE with a freshly
     * minted token. We only retry the cached path — a fresh token that
     * gets 401'd reflects an actual authorization problem (revoked
     * credentials / wrong scope), not a stale cache entry. */
    if (ret == EACCES && used_cached && !retried && cache_path != NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cached access_token rejected (HTTP 401); invalidating "
              "[%s] and retrying with a fresh grant.\n", cache_path);
        if (unlink(cache_path) != 0 && errno != ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Token cache unlink failed: %s.\n", strerror(errno));
        }
        retried = true;
        goto acquire_token;
    }

done:

    talloc_free(rest_ctx);
    return ret;
}
