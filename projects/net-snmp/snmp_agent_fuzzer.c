/*
 * Copyright 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This fuzzer exercises the SNMP PDU parsing code, and passes the
 * parsed PDUs to the SNMP agent to service the request.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/large_fd_set.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/agent/mib_modules.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define FAKE_FD 42
/*
 * These two globals are used to communicate between LLVMFuzzerTestOneInput()
 * and snmppcap_recv().  Don't try to multi-thread!  :-)
 */
const void *recv_data;
int recv_datalen;

int
fuzz_recv(netsnmp_transport *t, void *buf, int bufsiz, void **opaque, int *opaque_len)
{
    if (bufsiz > recv_datalen) {
        memcpy(buf, recv_data, recv_datalen);
        return recv_datalen;
    } else {
        return -1;
    }
}

int
fuzz_send(netsnmp_transport *t, const void *buf, int size,
	                     void **opaque, int *olength)
{
    /* We just report success at sending the response. */
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    netsnmp_session *ss;
    netsnmp_transport *transport;
    /*
     * Create a fake transport that allows us to
     * "receive" the PDUs that fuzzer is making up.
     */
    transport = SNMP_MALLOC_TYPEDEF(netsnmp_transport);
    /*
     * We set up just enough of the transport to fake the main
     * loop into calling us back.
     */
    transport->sock = FAKE_FD;        /* nobody actually uses this as a file descriptor */
    transport->f_recv = fuzz_recv;
    transport->f_send = fuzz_send;

    /*
     * Set up the callback in the same way that the
     * snmp agent does
     */
    ss = SNMP_MALLOC_TYPEDEF(netsnmp_session);
    snmp_sess_init(ss);
    ss->callback = handle_snmp_packet;
    ss->callback_magic = NULL;
    ss->securityModel = SNMP_SEC_MODEL_USM;

    /*
     * We use snmp_add() to specify the transport
     * explicitly.
     */
    snmp_add(ss, transport, NULL, NULL);

    if (init_agent("fuzz") != 0) {
	fprintf(stderr, "Initializing SNMP agent failed");
	exit(1);
    }
    init_mib_modules();
    init_snmp("fuzz");

    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        /*
         * Turn on all debugging, to help understand what
         * bits of the parser are running.
         */
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    netsnmp_large_fd_set lfdset;

    /*
     * Stash the data so it can be "received"
     */
    recv_data = data;
    recv_datalen = size;
    /*
     * This is admittedly a very strange way to invoke the API.
     * This is derived from snmppcap.c in the net-snmp distribution.
     * We registered above a transport that says "if FAKE_FD is
     * ready, call me to service it", and here we say "hey,
     * FAKE_FD is ready!"
     */
    netsnmp_large_fd_set_init(&lfdset, FD_SETSIZE);
    netsnmp_large_fd_setfd(FAKE_FD, &lfdset);
    snmp_read2(&lfdset);
    netsnmp_large_fd_set_cleanup(&lfdset);
    return 0;
}
