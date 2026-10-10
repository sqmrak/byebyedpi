#define _DEFAULT_SOURCE

#include "stl_gate.h"
#include "stl_log.h"
#include "stl_roots.h"
#include "stl_shadow.h"
#include "stl_hooks.h"

#include <Security/Security.h>
#include <string.h>

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);

#define STL_TRUST_RESULT_CONFIRM ((SecTrustResultType)2)

static int stl_trust_ok(SecTrustResultType r) {
    return r == kSecTrustResultUnspecified || r == kSecTrustResultProceed;
}

static const char *stl_trust_result_name(SecTrustResultType r) {
    switch (r) {
        case kSecTrustResultInvalid: return "invalid";
        case kSecTrustResultProceed: return "proceed";
        case STL_TRUST_RESULT_CONFIRM: return "confirm";
        case kSecTrustResultDeny: return "deny";
        case kSecTrustResultUnspecified: return "unspecified";
        case kSecTrustResultRecoverableTrustFailure: return "recoverable";
        case kSecTrustResultFatalTrustFailure: return "fatal";
        case kSecTrustResultOtherError: return "other";
        default: return "unknown";
    }
}

static int stl_should_retry_trust(OSStatus st, SecTrustResultType r) {
    if (st != errSecSuccess) return 1;
    if (stl_trust_ok(r)) return 0;
    return (r == kSecTrustResultRecoverableTrustFailure ||
            r == kSecTrustResultDeny ||
            r == kSecTrustResultFatalTrustFailure ||
            r == kSecTrustResultOtherError);
}

static OSStatus stl_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (!stl_gate_is_active())
        return orig_SecTrustEvaluate(trust, result);
    if (stl_shadow_trust_is_mine(trust)) {
        CFArrayRef ours = stl_roots_anchor_array();
        if (!ours) return orig_SecTrustEvaluate(trust, result);
        SecTrustSetAnchorCertificates(trust, ours);
        return orig_SecTrustEvaluate(trust, result);
    }

    OSStatus st = orig_SecTrustEvaluate(trust, result);
    if (!stl_should_retry_trust(st, result ? *result : kSecTrustResultInvalid))
        return st;

    if (result)
        stl_log("SecTrustEvaluate system -> os=%d trust=%s",
                (int)st, stl_trust_result_name(*result));

    CFArrayRef ours = stl_roots_anchor_array();
    if (!ours) return st;

    SecTrustSetAnchorCertificates(trust, ours);
    st = orig_SecTrustEvaluate(trust, result);
    if (!stl_trust_ok(result ? *result : kSecTrustResultInvalid) || st != errSecSuccess) {
        if (result)
            stl_log("SecTrustEvaluate bundled -> os=%d trust=%s",
                    (int)st, stl_trust_result_name(*result));
    }
    return st;
}

int stl_trust_install_hooks(void) {
    stl_hook_t hooks[] = {
        { "SecTrustEvaluate", (void *)stl_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate, 1 },
    };
    int installed = stl_hooks_install(hooks, sizeof(hooks) / sizeof(hooks[0]));
    stl_log("trust hooks: %d", installed);
    return installed < 0 ? -1 : 0;
}
