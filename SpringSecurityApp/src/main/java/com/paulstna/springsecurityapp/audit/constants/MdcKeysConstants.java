package com.paulstna.springsecurityapp.audit.constants;

import lombok.experimental.UtilityClass;

@UtilityClass
public final class MdcKeysConstants {

    public final String TRACE_ID = "traceId";
    public final String USER = "user";
    public final String IP = "ip";

    public final String EVENT_TYPE = "eventType";
    public final String EVENT_ACTION = "eventAction";

    public final String EVENT_OUTCOME = "eventOutcome";
    public final String FAILURE_REASON = "failureReason";

    public final String SEVERITY = "severity";

    public final String CLASS = "class";
    public final String METHOD = "method";
    public final String ERROR_TYPE = "errorType";
}