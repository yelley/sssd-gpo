/*
    Authors:
        Yassir Elley <yelley@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: GPO parsing tests

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

/* In order to access opaque types */
#include "providers/ad/ad_gpo.c"

#include "tests/cmocka/common_mock.h"

#define TARGET_DN "CN=F21-Client, OU=West OU,OU=Sales OU,DC=foo,DC=com"

bool gp_gplink_equal(struct gp_gplink *gplink1, struct gp_gplink *gplink2)
{

    if (gplink1 == gplink2) {
        DEBUG(SSSDBG_TRACE_FUNC, "return true equivalent\n");
        return true;
    }

    if (!gplink1) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false null gplink1\n");
        return false;
    }

    if (!gplink2) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false null gplink2\n");
        return false;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "gplink1->gpo_dn: %s\n", gplink1->gpo_dn);
    DEBUG(SSSDBG_TRACE_FUNC, "gplink2->gpo_dn: %s\n", gplink2->gpo_dn);

    if (strncmp(gplink1->gpo_dn, gplink2->gpo_dn, strlen(gplink2->gpo_dn)) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false gpo_dn\n");
        return false;
    }

    if (gplink1->enforced != gplink2->enforced) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false enforced\n");
        return false;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "return true\n");
    return true;

}


bool gp_som_equal(struct gp_som *som1, struct gp_som *som2)
{

    if (som1 == som2) {
        DEBUG(SSSDBG_TRACE_FUNC, "return true equivalent\n");
        return true;
    }

    if (!som1) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false null som1\n");
        return false;
    }

    if (!som2) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false null som2\n");
        return false;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "som1->som_dn: %s\n", som1->som_dn);
    DEBUG(SSSDBG_TRACE_FUNC, "som2->som_dn: %s\n", som2->som_dn);

    if (strncmp(som1->som_dn, som2->som_dn, strlen(som2->som_dn)) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false som_dn\n");
        return false;
    }

    if (som1->num_gplinks != som2->num_gplinks) {
        DEBUG(SSSDBG_TRACE_FUNC, "return false num_gplinks\n");
        return false;
    }

    int i;
    for (i=0; i<som2->num_gplinks; i++) {
        if (!gp_gplink_equal(som1->gplink_list[i], som2->gplink_list[i])) {
            DEBUG(SSSDBG_TRACE_FUNC, "return false gplink_list\n");
            return false;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "return true\n");
    return true;

}

struct ad_gpo_test_ctx {
    char *target_dn;
};


static struct ad_gpo_test_ctx *test_ctx;

void ad_gpo_test_setup(void **state)
{
    assert_true(leak_check_setup());
    test_ctx = talloc_zero(global_talloc_context,
                           struct ad_gpo_test_ctx);
    assert_non_null(test_ctx);

    //    test_ctx->target_dn = talloc_strdup(test_ctx, TARGET_DN);
    //    assert_non_null(test_ctx->target_dn);
}

void ad_gpo_test_teardown(void **state)
{
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
}

struct gpo_populate_som_list_result {
    const int result;
    const int num_soms;
    struct gp_som **som_list;
};

static void test_parse_generic(char *target_dn, struct gpo_populate_som_list_result *expected)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    int num_soms;
    int i;
    struct gp_som **som_list;
    assert_non_null(expected);

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    ret = ad_gpo_populate_som_list(tmp_ctx, target_dn, &num_soms, &som_list);

    assert_int_equal(ret, expected->result);
    assert_int_equal(num_soms, expected->num_soms);

    for (i=0; i<expected->num_soms; i++){
        bool equal = gp_som_equal(som_list[i], expected->som_list[i]);
        assert_int_equal(equal, true);
    }

    talloc_free(som_list);

done:
    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

/* Test parsing target dn into som components
 */
void test_populate_som_list(void **state)
{

    struct gp_som **som_list = talloc_array(test_ctx, struct gp_som *, 3 + 1);
    som_list[0] = talloc_zero(som_list, struct gp_som);
    som_list[0]->som_dn = talloc_strdup(som_list[0], "OU=West OU,OU=Sales OU,DC=foo,DC=com");
    som_list[1] = talloc_zero(som_list, struct gp_som);
    som_list[1]->som_dn = talloc_strdup(som_list[0], "OU=Sales OU,DC=foo,DC=com");
    som_list[2] = talloc_zero(som_list, struct gp_som);
    som_list[2]->som_dn = talloc_strdup(som_list[0], "DC=foo,DC=com");


    struct gpo_populate_som_list_result expected = {
        .result = EOK,
        .num_soms = 3,
        .som_list = som_list
    };

    char *target_dn = talloc_strdup(test_ctx, TARGET_DN);
    assert_non_null(target_dn);
    test_parse_generic(target_dn, &expected);
}
//som_list[0]->som_dn is OU=West OU,OU=Sales OU,DC=foo,DC=com
//som_list[1]->som_dn is OU=Sales OU,DC=foo,DC=com
//som_list[2]->som_dn is DC=foo,DC=com
//som_list[3]->som_dn is cn=Default-First-Site-Name,cn=Sites,CN=Configuration,DC=foo,DC=com

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_populate_som_list,
                                 ad_gpo_test_setup,
                                 ad_gpo_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_TRACE_FUNC;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    DEBUG(SSSDBG_TRACE_FUNC, "initialized\n");
    tests_set_cwd();

    return run_tests(tests);
}
