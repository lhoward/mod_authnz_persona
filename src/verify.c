/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Based in part, on mod_auth_memcookie, made by Mathieu CARBONNEAUX.
 *
 * See http://authmemcookie.sourceforge.net/ for details;
 * licensed under Apache License, Version 2.0.
 *
 * SHA-1 implementation by Steve Reid, steve@edmweb.com, in
 * public domain.
 */

#include "defines.h"
#include "cookie.h"
#include "verify.h"

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "apr_base64.h"

#include "browserid.h"

/*
 * process an assertion using the hosted verifier.
 */
VerifyResult processAssertion(request_rec *r, const char *assertion)
{
    BIDError err;
    BIDContext context = BID_C_NO_CONTEXT;
    BIDIdentity identity = BID_C_NO_IDENTITY;
    time_t expires;
    uint32_t flags = 0;
    char *origin = NULL;
    const char *issuer = NULL, *email = NULL;
    VerifyResult res = apr_pcalloc(r->pool, sizeof(struct _VerifyResult));

    err = BIDAcquireContext(NULL, /* szConfigFile */
                            BID_CONTEXT_RP | BID_CONTEXT_AUTHORITY_CACHE,
                            NULL, /* pvReserved */
                            &context);
    if (err != BID_S_OK)
        goto cleanup;

    if (ap_default_port(r)) {
        origin = apr_psprintf(r->pool, "%s://%s", ap_http_scheme(r),
                              r->server->server_hostname);
    } else {
        origin = apr_psprintf(r->pool, "%s://%s:%d",
                              ap_http_scheme(r), r->server->server_hostname,
                              r->server->port);
    }

    err = BIDVerifyAssertion(context, BID_C_NO_REPLAY_CACHE,
                             assertion, origin,
                             NULL, 0, apr_time_sec(r->request_time), 0, &identity,
                             &expires, &flags);
    if (err != BID_S_OK)
        goto cleanup;

    BIDGetIdentitySubject(context, identity, &email);
    res->verifiedEmail = apr_pstrdup(r->pool, email);

    BIDGetIdentityIssuer(context, identity, &issuer);
    res->identityIssuer = apr_pstrdup(r->pool, issuer);

cleanup:
    if (context != BID_C_NO_CONTEXT) {
        BIDReleaseIdentity(context, identity);
        BIDReleaseContext(context);
    }

    if (err != BID_S_OK) {
        const char *s;

        BIDErrorToString(err, &s);
        res->errorResponse = apr_psprintf(r->pool, "{\"status\":\"failure\",\"reason\":\"%s\"}", s);
    }

    return res;
}
