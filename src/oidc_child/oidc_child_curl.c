/*
    SSSD

    Helper child for OIDC and OAuth 2.0 Device Authorization Grant
    Curl based HTTP access

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <time.h>
#include "util/memory_erase.h"
#include "oidc_child/oidc_child_util.h"

struct rest_ctx {
    bool libcurl_debug;
    const char *ca_db;
    char *http_data;
    CURL *curl_ctx;
};

static CURL *init_curl(void)
{
    CURL *curl_ctx;
    CURLcode res;

    res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize libcurl.\n");
        return NULL;
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl context.\n");
        curl_global_cleanup();
        return NULL;
    }

    return curl_ctx;
}

static int rest_ctx_destructor(void *p);
struct rest_ctx *get_rest_ctx(TALLOC_CTX *mem_ctx, bool libcurl_debug,
                              const char *ca_db)
{
    struct rest_ctx *rest_ctx;

    rest_ctx = talloc_zero(mem_ctx, struct rest_ctx);
    if (rest_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate curl context.\n");
        goto fail;
    }

    rest_ctx->libcurl_debug = libcurl_debug;
    if (ca_db != NULL) {
        rest_ctx->ca_db = talloc_strdup(rest_ctx, ca_db);
        if (rest_ctx->ca_db == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to allocate memory for CA DB string.\n");
            goto fail;
        }
    }

    rest_ctx->curl_ctx = init_curl();
    if (rest_ctx->curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        goto fail;
    }

    talloc_set_destructor((TALLOC_CTX *) rest_ctx, rest_ctx_destructor);
    return rest_ctx;

fail:
    talloc_free(rest_ctx);
    return NULL;
}

const char *get_http_data(struct rest_ctx *rest_ctx)
{
    return (const char *) rest_ctx->http_data;
}

errno_t set_http_data(struct rest_ctx *rest_ctx, const char *str)
{
    char *tmp;

    tmp = talloc_strdup(rest_ctx, str);
    if (tmp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy string.\n");
        return ENOMEM;
    }

    rest_ctx->http_data = tmp;

    return EOK;
}

char *url_encode_string(struct rest_ctx *rest_ctx, const char *inp)
{
    char *tmp;
    char *out = NULL;

    if (inp == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Empty input.\n");
        return NULL;
    }

    tmp = curl_easy_escape(rest_ctx->curl_ctx, inp, 0);
    if (tmp == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "curl_easy_escape failed for [%s].\n", inp);
        goto done;
    }

    out = talloc_strdup(rest_ctx, tmp);
    curl_free(tmp);
    if (out == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "talloc_strdup failed.\n");
        goto done;
    }

done:
    return out;
}

static char *append_to_post_data(char *str, const char *key, const char *val)
{
    CURL *curl_ctx = NULL;
    char *key_enc = NULL;
    char *val_enc = NULL;
    char *out = NULL;
    const char *fmt = str != NULL && *str != '\0' ? "&%s=%s" : "%s=%s";

    if (key == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Missing key.\n");
        return NULL;
    }

    if (val == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Missing value.\n");
        return NULL;
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        return NULL;
    }

    key_enc = curl_easy_escape(curl_ctx, key, 0);
    if (key_enc == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "curl_easy_escape failed for key [%s].\n", key);
        goto done;
    }

    val_enc = curl_easy_escape(curl_ctx, val, 0);
    if (val_enc == NULL) {
        /* Do not write secrets into logs if curl fails escaping. */
        DEBUG(SSSDBG_TRACE_ALL, "curl_easy_escape failed for value of [%s].\n", key);
        goto done;
    }

    out = talloc_asprintf_append(str, fmt, key_enc, val_enc);
    if (out == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "talloc_asprintf_append failed.\n");
        goto done;
    }

done:
    curl_free(key_enc);
    curl_free(val_enc);
    curl_easy_cleanup(curl_ctx);
    return out;
}

/* The curl write_callback will always append the received data. To start a
 * new string call clean_http_data() before the curl request.*/
void clean_http_data(struct rest_ctx *rest_ctx)
{
    talloc_free(rest_ctx->http_data);
    rest_ctx->http_data = NULL;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
    size_t realsize = size * nmemb;
    struct rest_ctx *rest_ctx = (struct rest_ctx *) userdata;
    char *tmp = NULL;

    DEBUG_SENSITIVE(SSSDBG_TRACE_ALL, "%.*s\n", (int) realsize, ptr);

    tmp = talloc_asprintf(rest_ctx, "%s%.*s",
                          rest_ctx->http_data == NULL ? "" : rest_ctx->http_data,
                          (int) realsize, ptr);
    talloc_free(rest_ctx->http_data);
    sss_erase_mem_securely(ptr, realsize);
    rest_ctx->http_data = tmp;
    if (rest_ctx->http_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy received data.\n");
        return 0;
    }
    talloc_set_destructor((void *) rest_ctx->http_data,
                          sss_erase_talloc_mem_securely);

    return realsize;
}

static int libcurl_debug_callback(CURL *curl_ctx, curl_infotype type,
                                  char *data, size_t size, void *userptr)
{
    static const char prefix[CURLINFO_END][3] = {
                                     "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };

    switch (type) {
    case CURLINFO_TEXT:
    case CURLINFO_HEADER_IN:
    case CURLINFO_HEADER_OUT:
        sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, SSSDBG_TRACE_ALL,
                     "libcurl: %s%.*s", prefix[type], (int) size, data);
        break;
    default:
        break;
    }

    return 0;
}

static errno_t set_http_opts(CURL *curl_ctx, struct rest_ctx *rest_ctx,
                             const char *uri, const char *post_data,
                             const char *token, struct curl_slist *headers)
{
    CURLcode res;
    int ret;

    /* Only allow https */
#ifdef HAVE_CURLOPT_PROTOCOLS_STR
    res = curl_easy_setopt(curl_ctx, CURLOPT_PROTOCOLS_STR, "https");
#else
    res = curl_easy_setopt(curl_ctx, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
#endif
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to enforce HTTPS.\n");
        ret = EIO;
        goto done;
    }

    if (rest_ctx->ca_db != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_CAINFO, rest_ctx->ca_db);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set CA DB path.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_URL, uri);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set URL.\n");
        ret = EIO;
        goto done;
    }

    if (rest_ctx->libcurl_debug) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_VERBOSE, 1L);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set verbose option.\n");
            ret = EIO;
            goto done;
        }
        res = curl_easy_setopt(curl_ctx, CURLOPT_DEBUGFUNCTION,
                               libcurl_debug_callback);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set debug callback.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_USERAGENT, "SSSD oidc_child/0.0");
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set useragent option.\n");
        ret = EIO;
        goto done;
    }

    if (headers != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_HTTPHEADER, headers);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add header to POST request.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_WRITEFUNCTION, write_callback);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add write callback.\n");
        ret = EIO;
        goto done;
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_WRITEDATA, rest_ctx);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add write callback data.\n");
        ret = EIO;
        goto done;
    }

    if (post_data != NULL) {
        /* Don't log 'post_data' content as it might contain 'secret' */
        DEBUG(SSSDBG_TRACE_ALL, "Setting POST data.\n");
        res = curl_easy_setopt(curl_ctx, CURLOPT_POSTFIELDS, post_data);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add data to POST request.\n");
            ret = EIO;
            goto done;
        }
    }

    if (token != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set HTTP auth.\n");
            ret = EIO;
            goto done;
        }
        res = curl_easy_setopt(curl_ctx, CURLOPT_XOAUTH2_BEARER, token);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add token.\n");
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;
done:

    return ret;
}

#define ACCEPT_JSON "Accept: application/json"
#define CONTENT_JSON "Content-Type: application/json"

static errno_t do_http_request_ext(struct rest_ctx *rest_ctx, const char *uri,
                                   const char *post_data, const char *token,
                                   const char **extra_headers)
{
    CURL *curl_ctx = NULL;
    CURLcode res;
    int ret;
    long resp_code;
    struct curl_slist *headers = NULL;
    size_t c;

    headers = curl_slist_append(headers, ACCEPT_JSON);
    if (headers == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create Accept header, trying without.\n");
    }

    if (extra_headers != NULL) {
        for (c = 0; extra_headers[c] != NULL; c++) {
            headers = curl_slist_append(headers, extra_headers[c]);
            if (headers == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to create header [%s], trying without.\n",
                      extra_headers[c]);
            }
        }
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        ret = EIO;
        goto done;
    }

    ret = set_http_opts(curl_ctx, rest_ctx, uri, post_data, token, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set http options.\n");
        goto done;
    }

    res = curl_easy_perform(curl_ctx);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send request.\n");
        ret = EIO;
        goto done;
    }

    res = curl_easy_getinfo(curl_ctx, CURLINFO_RESPONSE_CODE, &resp_code);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get response code.\n");
        ret = EIO;
        goto done;
    }

    if (resp_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "Request failed, response code is [%ld].\n",
                                 resp_code);
        DEBUG(SSSDBG_OP_FAILURE, "Error response body: [%s].\n",
                                 get_http_data(rest_ctx));
        /* 401 = bearer rejected (token revoked / expired / wrong scope).
         * Distinct return code so the caller can invalidate the on-disk
         * token cache and retry with a fresh grant. Other non-200s stay EIO. */
        ret = (resp_code == 401) ? EACCES : EIO;
        goto done;
    }

    ret = EOK;
done:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_ctx);
    return ret;
}

errno_t do_http_request_json_data(struct rest_ctx *rest_ctx, const char *uri,
                                  const char *post_data, const char *token)
{
    const char *extra_headers[] = {CONTENT_JSON, NULL};

    return do_http_request_ext(rest_ctx, uri, post_data, token, extra_headers);
}

errno_t do_http_request(struct rest_ctx *rest_ctx, const char *uri,
                        const char *post_data, const char *token)
{
    CURL *curl_ctx = NULL;
    CURLcode res;
    int ret;
    long resp_code;
    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, ACCEPT_JSON);
    if (headers == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create Accept header, trying without.\n");
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        ret = EIO;
        goto done;
    }

    ret = set_http_opts(curl_ctx, rest_ctx, uri, post_data, token, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set http options.\n");
        goto done;
    }

    res = curl_easy_perform(curl_ctx);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send request.\n");
        ret = EIO;
        goto done;
    }

    res = curl_easy_getinfo(curl_ctx, CURLINFO_RESPONSE_CODE, &resp_code);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get response code.\n");
        ret = EIO;
        goto done;
    }

    if (resp_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "Request failed, response code is [%ld].\n",
                                 resp_code);
        DEBUG(SSSDBG_OP_FAILURE, "Error response body: [%s].\n",
                                 get_http_data(rest_ctx));
        /* 401 = bearer rejected (token revoked / expired / wrong scope).
         * Distinct return code so the caller can invalidate the on-disk
         * token cache and retry with a fresh grant. Other non-200s stay EIO. */
        ret = (resp_code == 401) ? EACCES : EIO;
        goto done;
    }

    ret = EOK;
done:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_ctx);
    return ret;
}

#define AZURE_EXPECT_CODE "The request body must contain the following parameter: 'code'."

errno_t get_token(TALLOC_CTX *mem_ctx,
                  struct devicecode_ctx *dc_ctx, const char *client_id,
                  const char *client_secret,
                  bool get_device_code)
{
    CURL *curl_ctx = NULL;
    CURLcode res;
    int ret;
    size_t waiting_time = 0;
    char *error_description = NULL;
    char *post_data = NULL;
    struct curl_slist *headers = NULL;
    bool azure_fallback = false;
    size_t device_code_sep;

    headers = curl_slist_append(headers, ACCEPT_JSON);
    if (headers == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create Accept header, trying without.\n");
    }

    post_data = talloc_strdup(mem_ctx, "grant_type=urn:ietf:params:oauth:grant-type:device_code");
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "client_id", client_id);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_id to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    if (client_secret != NULL) {
        post_data = append_to_post_data(post_data, "client_secret", client_secret);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_secret to POST data.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    /* Remember the offset of the device code for the azure fallback later. */
    device_code_sep = strlen(post_data);

    post_data = append_to_post_data(post_data, "device_code", dc_ctx->device_code);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add device_code to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        ret = EIO;
        goto done;
    }

    ret = set_http_opts(curl_ctx, dc_ctx->rest_ctx, dc_ctx->token_endpoint,
                        post_data, NULL, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set http options.\n");
        goto done;
    }

    do {
        clean_http_data(dc_ctx->rest_ctx);

        res = curl_easy_perform(curl_ctx);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to send token request.\n");
            ret = EIO;
            goto done;
        }

        talloc_zfree(error_description);
        ret = parse_token_result(dc_ctx, &error_description);
        if (ret != EAGAIN) {
            if (ret == EIO && !azure_fallback && error_description != NULL
                    && strstr(error_description, AZURE_EXPECT_CODE) != NULL) {
                /* Older Azure AD v1 endpoints expect 'code' instead of the RFC
                 * conforming 'device_code', see e.g.
                 * https://docs.microsoft.com/de-de/archive/blogs/azuredev/assisted-login-using-the-oauth-deviceprofile-flow
                 * and search for 'request_content' in the code example. */
                post_data[device_code_sep] = '\0';
                post_data = append_to_post_data(post_data, "code",
                                                           dc_ctx->device_code);
                if (post_data == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "Failed to add code to POST data.\n");
                    ret = ENOMEM;
                    goto done;
                }
                azure_fallback = true;
                continue;
            }
            break;
        }

        /* only run once after getting the device code to tell the IdP we are
         * expecting that the user will connect */
        if (get_device_code) {
            if (ret == EAGAIN) {
                ret = EOK;
            }
            break;
        }

        waiting_time += dc_ctx->interval;
        if (waiting_time >= dc_ctx->expires_in) {
            /* Next sleep will end after the request is expired on the
             * server side, so we can just error out now. */
            ret = ETIMEDOUT;
            break;
        }
        sleep(dc_ctx->interval);
    } while (waiting_time < dc_ctx->expires_in);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get token.\n");
    }

done:
    talloc_free(post_data);
    talloc_free(error_description);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_ctx);
    return ret;
}

errno_t get_openid_configuration(struct devicecode_ctx *dc_ctx,
                                 const char *issuer_url)
{
    int ret;
    char *uri = NULL;
    bool has_slash = false;

    if (issuer_url[strlen(issuer_url) - 1] == '/') {
        has_slash = true;
    }

    uri = talloc_asprintf(dc_ctx, "%s%s.well-known/openid-configuration",
                                   issuer_url, has_slash ? "" : "/");
    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for config url.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(dc_ctx->rest_ctx);
    ret = do_http_request(dc_ctx->rest_ctx, uri, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "http request failed.\n");
    }

done:
    talloc_free(uri);

    return ret;
}

#define DEFAULT_SCOPE "user"

errno_t get_devicecode(struct devicecode_ctx *dc_ctx,
                       const char *client_id, const char *client_secret)
{
    int ret;
    char *post_data = NULL;
    const char *scope = dc_ctx->scope != NULL ? dc_ctx->scope : DEFAULT_SCOPE;

    post_data = talloc_strdup(dc_ctx, "");
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "client_id", client_id);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_id to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "scope", scope);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add scope to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    if (client_secret != NULL) {
        post_data = append_to_post_data(post_data, "client_secret", client_secret);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_secret to POST data.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    clean_http_data(dc_ctx->rest_ctx);
    ret = do_http_request(dc_ctx->rest_ctx,
                          dc_ctx->device_authorization_endpoint,
                          post_data, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send device code request.\n");
    }

done:
    talloc_free(post_data);
    return ret;
}

errno_t get_userinfo(struct devicecode_ctx *dc_ctx)
{
    int ret;

    clean_http_data(dc_ctx->rest_ctx);
    ret = do_http_request(dc_ctx->rest_ctx, dc_ctx->userinfo_endpoint, NULL,
                          dc_ctx->td->access_token_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send userinfo request.\n");
    }

    return ret;
}

errno_t get_jwks(struct devicecode_ctx *dc_ctx)
{
    int ret;

    clean_http_data(dc_ctx->rest_ctx);
    ret = do_http_request(dc_ctx->rest_ctx, dc_ctx->jwks_uri, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read jwks file [%s].\n",
                                 dc_ctx->jwks_uri);
    }

    return ret;

}

static int rest_ctx_destructor(void *p)
{
    struct rest_ctx *rest_ctx = talloc_get_type(p, struct rest_ctx);

    curl_easy_cleanup(rest_ctx->curl_ctx);
    curl_global_cleanup();

    return 0;
}

errno_t client_credentials_grant(struct rest_ctx *rest_ctx,
                                 const char *token_endpoint,
                                 const char *client_id,
                                 const char *client_secret,
                                 const char *scope)
{
    int ret;
    char *post_data = NULL;

    post_data = talloc_strdup(rest_ctx, "grant_type=client_credentials");
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "client_id", client_id);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_id to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "client_secret", client_secret);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_secret to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    if (scope != NULL) {
        post_data = append_to_post_data(post_data, "scope", scope);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add scope to POST data.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, token_endpoint, post_data, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send device code request.\n");
    }

done:
    talloc_free(post_data);
    return ret;
}

/* Base64url-encode raw bytes (no padding, url-safe alphabet). */
static char *base64url_encode(TALLOC_CTX *mem_ctx,
                               const unsigned char *data, size_t len)
{
    BIO *b64_bio = NULL;
    BIO *mem_bio = NULL;
    BUF_MEM *mem_buf;
    char *out = NULL;
    char *p;

    b64_bio = BIO_new(BIO_f_base64());
    if (b64_bio == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "BIO_new(BIO_f_base64) failed.\n");
        goto done;
    }

    mem_bio = BIO_new(BIO_s_mem());
    if (mem_bio == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "BIO_new(BIO_s_mem) failed.\n");
        goto done;
    }

    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64_bio, mem_bio);

    if (BIO_write(b64_bio, data, (int) len) != (int) len) {
        DEBUG(SSSDBG_OP_FAILURE, "BIO_write failed.\n");
        goto done;
    }
    if (BIO_flush(b64_bio) != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "BIO_flush failed.\n");
        goto done;
    }

    BIO_get_mem_ptr(mem_bio, &mem_buf);
    out = talloc_strndup(mem_ctx, mem_buf->data, mem_buf->length);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        goto done;
    }

    /* Convert to base64url: + -> -, / -> _, strip = padding */
    for (p = out; *p != '\0'; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; }
    }

done:
    /* mem_bio is owned by b64_bio after BIO_push */
    if (b64_bio != NULL) BIO_free_all(b64_bio);
    return out;
}

/* Build a signed JWT for private_key_jwt client authentication (RFC 7523).
 * Supports RSA keys (RS256). The key file must be a PEM private key. */
static char *build_private_key_jwt(TALLOC_CTX *mem_ctx,
                                    const char *client_id,
                                    const char *token_endpoint,
                                    const char *key_file,
                                    const char *kid)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    FILE *fp = NULL;
    char *header_b64 = NULL;
    char *payload_b64 = NULL;
    char *signing_input = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    char *sig_b64 = NULL;
    char *jwt = NULL;
    unsigned char jti_raw[16];
    char jti[33];
    time_t now;
    const char *alg;
    char *header_json = NULL;
    char *payload_json = NULL;
    int key_type;
    int i;

    fp = fopen(key_file, "r");
    if (fp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to open private key file [%s]: [%d][%s].\n",
              key_file, errno, strerror(errno));
        goto done;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;
    if (pkey == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read private key from [%s].\n", key_file);
        goto done;
    }

    key_type = EVP_PKEY_base_id(pkey);
    if (key_type == EVP_PKEY_RSA) {
        alg = "RS256";
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unsupported key type [%d]; only RSA keys are supported.\n",
              key_type);
        goto done;
    }

    /* Generate a random JTI */
    if (RAND_bytes(jti_raw, sizeof(jti_raw)) != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate random JTI.\n");
        goto done;
    }
    for (i = 0; i < 16; i++) {
        snprintf(jti + i * 2, 3, "%02x", jti_raw[i]);
    }

    now = time(NULL);

    header_json = (kid != NULL)
        ? talloc_asprintf(mem_ctx,
                          "{\"alg\":\"%s\",\"typ\":\"JWT\",\"kid\":\"%s\"}",
                          alg, kid)
        : talloc_asprintf(mem_ctx, "{\"alg\":\"%s\",\"typ\":\"JWT\"}", alg);
    if (header_json == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed for JWT header.\n");
        goto done;
    }

    payload_json = talloc_asprintf(mem_ctx,
        "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\","
        "\"iat\":%ld,\"exp\":%ld,\"jti\":\"%s\"}",
        client_id, client_id, token_endpoint,
        (long) now, (long) (now + 300), jti);
    if (payload_json == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed for JWT payload.\n");
        goto done;
    }

    header_b64 = base64url_encode(mem_ctx,
                                   (unsigned char *) header_json,
                                   strlen(header_json));
    if (header_b64 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to base64url-encode JWT header.\n");
        goto done;
    }

    payload_b64 = base64url_encode(mem_ctx,
                                    (unsigned char *) payload_json,
                                    strlen(payload_json));
    if (payload_b64 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to base64url-encode JWT payload.\n");
        goto done;
    }

    signing_input = talloc_asprintf(mem_ctx, "%s.%s", header_b64, payload_b64);
    if (signing_input == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed for signing input.\n");
        goto done;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_MD_CTX_new failed.\n");
        goto done;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_DigestSignInit failed.\n");
        goto done;
    }

    if (EVP_DigestSignUpdate(md_ctx, signing_input, strlen(signing_input)) != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_DigestSignUpdate failed.\n");
        goto done;
    }

    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) != 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "EVP_DigestSignFinal (length query) failed.\n");
        goto done;
    }

    sig = talloc_size(mem_ctx, sig_len);
    if (sig == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate signature buffer.\n");
        goto done;
    }

    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_DigestSignFinal failed.\n");
        talloc_free(sig);
        sig = NULL;
        goto done;
    }

    sig_b64 = base64url_encode(mem_ctx, sig, sig_len);
    if (sig_b64 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to base64url-encode signature.\n");
        goto done;
    }

    jwt = talloc_asprintf(mem_ctx, "%s.%s", signing_input, sig_b64);
    if (jwt == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed for JWT.\n");
    }

done:
    if (sig != NULL) {
        sss_erase_mem_securely(sig, sig_len);
        talloc_free(sig);
    }
    if (pkey != NULL) EVP_PKEY_free(pkey);
    if (md_ctx != NULL) EVP_MD_CTX_free(md_ctx);
    talloc_free(header_json);
    talloc_free(payload_json);
    return jwt;
}

errno_t client_credentials_grant_jwt(struct rest_ctx *rest_ctx,
                                     const char *token_endpoint,
                                     const char *client_id,
                                     const char *private_key_file,
                                     const char *kid,
                                     const char *scope)
{
    int ret;
    char *post_data = NULL;
    char *jwt = NULL;

    jwt = build_private_key_jwt(rest_ctx, client_id, token_endpoint,
                                private_key_file, kid);
    if (jwt == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build private_key_jwt.\n");
        ret = EIO;
        goto done;
    }

    post_data = talloc_strdup(rest_ctx, "grant_type=client_credentials");
    if (post_data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "client_id", client_id);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_id to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    if (scope != NULL) {
        post_data = append_to_post_data(post_data, "scope", scope);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add scope to POST data.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    post_data = append_to_post_data(post_data, "client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to add client_assertion_type to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "client_assertion", jwt);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to add client_assertion to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, token_endpoint, post_data, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to send client credentials JWT request.\n");
    }

done:
    talloc_free(post_data);
    talloc_free(jwt);
    return ret;
}

errno_t refresh_token(TALLOC_CTX *mem_ctx,
                      struct devicecode_ctx *dc_ctx, const char *client_id,
                      const char *client_secret,
                      const char *token)
{
    int ret;
    char *error_description = NULL;
    char *post_data = NULL;
    const char *scope = dc_ctx->scope != NULL ? dc_ctx->scope : DEFAULT_SCOPE;

    post_data = talloc_strdup(mem_ctx, "grant_type=refresh_token");
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "refresh_token", token);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add refresh_token to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    post_data = append_to_post_data(post_data, "client_id", client_id);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_id to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    if (client_secret != NULL) {
        post_data = append_to_post_data(post_data, "client_secret", client_secret);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add client_secret to POST data.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    post_data = append_to_post_data(post_data, "scope", scope);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add scope to POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(dc_ctx->rest_ctx);

    ret = do_http_request(dc_ctx->rest_ctx, dc_ctx->token_endpoint, post_data,
                          NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "http request failed.\n");
        goto done;
    }

    ret = parse_token_result(dc_ctx, &error_description);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get token.\n");
        goto done;
    }

done:
    talloc_free(post_data);
    talloc_free(error_description);
    return ret;
}
