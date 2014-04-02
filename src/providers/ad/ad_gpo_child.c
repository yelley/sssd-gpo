/*
    SSSD

    AD GPO Backend Module -- perform SMB and CSE processing in a child process

    Authors:
        Yassir Elley <yelley@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <popt.h>
#include <samba-4.0/libsmbclient.h>
#include <ini_configobj.h>
#include <ini_config.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/child_common.h"
#include "providers/dp_backend.h"
#include "sss_cli.h"

#define RIGHTS_SECTION "Privilege Rights"
#define ALLOW_LOGON_LOCALLY "SeInteractiveLogonRight"
#define DENY_LOGON_LOCALLY "SeDenyInteractiveLogonRight"
#define SMB_BUFFER_SIZE 65536

struct input_buffer {
    const char *smb_uri;
    uint32_t container_version;
};

static errno_t unpack_buffer(uint8_t *buf, size_t size,
                             struct input_buffer *ibuf)
{
    size_t p = 0;
    uint32_t len;

    DEBUG(SSSDBG_TRACE_FUNC, "total buffer size: %zu\n", size);

    /* smb_uri size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_FUNC, "smb_uri size: %d\n", len);
    if (len) {
        if ((p + len ) > size) return EINVAL;
        ibuf->smb_uri = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(SSSDBG_TRACE_FUNC, "got smb_uri: %s\n", ibuf->smb_uri);
        if (ibuf->smb_uri == NULL) return ENOMEM;
        p += len;
    }

    return EOK;
}


static int pack_buffer(struct response *r, int result, int allowed_size, char **allowed_sids, int denied_size, char **denied_sids)
{
    int len = 0;
    size_t p = 0;
    int i;

    /* A buffer with the following structure must be created:
     * int32_t status of the request (required)
     * int32_t allowed_size  (required)
     * uint8_t[allowed_size] (optional if allowed_size == 0)
     * int32_t denied_size   (required)
     * uint8_t[denied_size]  (optional if denied_size == 0)
     */

    DEBUG(SSSDBG_TRACE_FUNC, "entering pack_buffer\n");

    for (i = 0; i < allowed_size; i++) {
        len += strlen(allowed_sids[i]);
    }

    for (i = 0; i < denied_size; i++) {
        len += strlen(denied_sids[i]);
    }

    r->size = (3 + allowed_size + denied_size) * sizeof(uint32_t) + len;

    DEBUG(SSSDBG_TRACE_FUNC, "response size: %zu\n",r->size);

    r->buf = talloc_array(r, uint8_t, r->size);
    if(!r->buf) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "result [%d] allowed_size [%d] denied_size [%d]\n",
          result, allowed_size, denied_size);

    /* result */
    SAFEALIGN_SET_UINT32(&r->buf[p], result, &p);

    /* allowed_size */
    SAFEALIGN_SET_UINT32(&r->buf[p], allowed_size, &p);

    int sid_len = 0;
    for (i = 0; i < allowed_size; i++) {
        sid_len = strlen(allowed_sids[i]);
        SAFEALIGN_SET_UINT32(&r->buf[p], sid_len, &p);
        safealign_memcpy(&r->buf[p], allowed_sids[i], sid_len, &p);
    }

    /* denied_size */
    SAFEALIGN_SET_UINT32(&r->buf[p], denied_size, &p);
    for (i = 0; i < denied_size; i++) {
        sid_len = strlen(denied_sids[i]);
        SAFEALIGN_SET_UINT32(&r->buf[p], sid_len, &p);
        safealign_memcpy(&r->buf[p], denied_sids[i], sid_len, &p);
    }

    return EOK;
}

static int prepare_response(TALLOC_CTX *mem_ctx,
                            int result,
                            int allowed_size,
                            char **allowed_sids,
                            int denied_size,
                            char **denied_sids,
                            struct response **rsp)
{
    int ret;
    struct response *r = NULL;
    DEBUG(SSSDBG_TRACE_FUNC, "entering prepare_response.\n");
    r = talloc_zero(mem_ctx, struct response);
    if (!r) return ENOMEM;

    r->buf = NULL;
    r->size = 0;

    ret = pack_buffer(r, result, allowed_size, allowed_sids, denied_size, denied_sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_buffer failed\n");
        return ret;
    }

    *rsp = r;
    DEBUG(SSSDBG_TRACE_FUNC, "r->size: %zu\n", r->size);
    return EOK;
}

static errno_t
parse_logon_right_with_libini(struct ini_cfgobj *ini_config,
                              const char *section,
                              const char *name,
                              int *_size,
                              char ***_sids)
{
  int ret = 0;
  struct value_obj *vobj = NULL;
  char **sids = NULL;
  int num_sids;
  int i;

  ret = ini_get_config_valueobj(section, name, ini_config, INI_GET_FIRST_VALUE,
                                &vobj);
  if (vobj == NULL) {
      DEBUG(SSSDBG_CRIT_FAILURE, "section/name not found: [%s][%s]\n",
            section, name);
      return EOK;
  }
  sids = ini_get_string_config_array(vobj, NULL, &num_sids, &ret);

  if (ret) {
      DEBUG(SSSDBG_CRIT_FAILURE,
            "ini_get_string_config_array failed [%d][%s]\n", ret, strerror(ret));
      return ret;
  }

  for (i = 0; i <num_sids; i++) {
    if (sids[i][0] == '*') {
      sids[i]++;
    }
  }

  *_size = num_sids;
  *_sids = sids;

  return EOK;
}

static errno_t
ad_gpo_parse_security_cse_buffer(uint8_t *data_buf,
                                 int data_len,
                                 char ***allowed_sids,
                                 int *allowed_size,
                                 char ***denied_sids,
                                 int *denied_size)
{
    struct ini_cfgfile *file_ctx = NULL;
    struct ini_cfgobj *ini_config = NULL;
    int ret;
    char **allow_sids = NULL; char **deny_sids = NULL;
    int allow_size = 0; int deny_size = 0;

    ret = ini_config_create(&ini_config);
    if (ret) goto done;
    ret = ini_config_file_from_mem(data_buf, data_len, &file_ctx);
    if (ret) goto done;
    ret = ini_config_parse(file_ctx, INI_STOP_ON_NONE, 0, 0, ini_config);
    if (ret) goto done;

    ret = parse_logon_right_with_libini(ini_config,
                                        RIGHTS_SECTION,
                                        ALLOW_LOGON_LOCALLY,
                                        &allow_size,
                                        &allow_sids);
    if (ret) {goto done;}

    ret = parse_logon_right_with_libini(ini_config,
                                        RIGHTS_SECTION,
                                        DENY_LOGON_LOCALLY,
                                        &deny_size,
                                        &deny_sids);
    if (ret) {goto done;}

    *allowed_sids = allow_sids;
    *allowed_size = allow_size;
    *denied_sids = deny_sids;
    *denied_size = deny_size;

 done:

    if (ret) {
      DEBUG(SSSDBG_CRIT_FAILURE, "Error encountered: %d.\n", ret);
    }

    ini_config_file_close(file_ctx);
    return ret;
}

static void
sssd_krb_get_auth_data_fn(const char * pServer,
                     const char * pShare,
                     char * pWorkgroup,
                     int maxLenWorkgroup,
                     char * pUsername,
                     int maxLenUsername,
                     char * pPassword,
                     int maxLenPassword)
{
    /* since we are using kerberos for authentication, we simply return */
    return;
}


/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) opens an SMB connection,
 * retrieves the data referenced by the input smb_uri, and then closes the SMB
 * connection. The data is then parsed and the results are used to populate the
 * output parameters with the list of allowed_sids and denied_sids
 */
static errno_t
gpo_child_process_security_settings_cse(TALLOC_CTX *mem_ctx,
                              const char *smb_uri,
                              char ***_allowed_sids,
                              int *_allowed_size,
                              char ***_denied_sids,
                              int *_denied_size)
{
    SMBCCTX *context;
    int ret = 0;
    uint8_t *buf = NULL;
    int bytesread = 0;

    char **allowed_sids;
    char **denied_sids;
    int allowed_size = 0;
    int denied_size = 0;

    DEBUG(SSSDBG_TRACE_ALL, "%s\n", smb_uri);

    context = smbc_new_context();
    if (!context) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not allocate new smbc context\n");
    }

    smbc_setFunctionAuthData(context, sssd_krb_get_auth_data_fn);
    smbc_setOptionUseKerberos(context, 1);
    /* TBD: figure out whether we need the following function call */
    /* smbc_setOptionFallbackAfterKerberos(context, 1); */

    /* Initialize the context using the previously specified options */
    if (!smbc_init_context(context)) {
        smbc_free_context(context, 0);
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not initialize smbc context\n");
    }

    /* Tell the compatibility layer to use this context */
    smbc_set_context(context);

    int remotehandle = smbc_open(smb_uri, O_RDONLY, 0755);
    if (remotehandle < 0) DEBUG(SSSDBG_CRIT_FAILURE, "smbc_open failed\n");

    buf = talloc_array(mem_ctx, uint8_t, SMB_BUFFER_SIZE);
    bytesread = smbc_read(remotehandle, buf, SMB_BUFFER_SIZE);
    if(bytesread < 0) DEBUG(SSSDBG_CRIT_FAILURE, "smbc_read failed\n");

    DEBUG(SSSDBG_CRIT_FAILURE, "bytesread: %d\n", bytesread);

    smbc_close(remotehandle);

    ret = ad_gpo_parse_security_cse_buffer(buf,
                                           bytesread,
                                           &allowed_sids,
                                           &allowed_size,
                                           &denied_sids,
                                           &denied_size);

    /* TBD: allowed/denied_sids/size should be stored in cache */

    *_allowed_sids = allowed_sids;
    *_allowed_size = allowed_size;
    *_denied_sids = denied_sids;
    *_denied_size = denied_size;

    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int debug_fd = -1;
    errno_t ret;
    int result;
    TALLOC_CTX *main_ctx = NULL;
    uint8_t *buf = NULL;
    ssize_t len = 0;
    struct input_buffer *ibuf = NULL;
    struct response *resp = NULL;
    size_t written;
    char **allowed_sids;
    int allowed_size;
    char **denied_sids;
    int denied_size;
    int j;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0,
         _("Debug level"), NULL},
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0,
         _("Add debug timestamps"), NULL},
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0,
         _("Show timestamps with microseconds"), NULL},
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    debug_prg_name = talloc_asprintf(NULL, "[sssd[gpo_child[%d]]]", getpid());
    if (!debug_prg_name) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    if (debug_fd != -1) {
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "set_debug_file_from_fd failed.\n");
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "gpo_child started.\n");

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        talloc_free(discard_const(debug_prg_name));
        goto fail;
    }
    talloc_steal(main_ctx, debug_prg_name);

    buf = talloc_size(main_ctx, sizeof(uint8_t)*IN_BUF_SIZE);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        goto fail;
    }

    ibuf = talloc_zero(main_ctx, struct input_buffer);
    if (ibuf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "context initialized\n");

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "read failed [%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    close(STDIN_FILENO);

    ret = unpack_buffer(buf, len, ibuf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "unpack_buffer failed.[%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "processing security settings\n");

    result = gpo_child_process_security_settings_cse(main_ctx,
                                                     ibuf->smb_uri,
                                                     &allowed_sids,
                                                     &allowed_size,
                                                     &denied_sids,
                                                     &denied_size);

    DEBUG(SSSDBG_CRIT_FAILURE, "allowed_size = %d\n", allowed_size);
    for (j= 0; j < allowed_size; j++) {
        DEBUG(SSSDBG_CRIT_FAILURE, "allowed_sids[%d] = %s\n", j,
              allowed_sids[j]);
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "denied_size = %d\n", denied_size);
    for (j= 0; j < denied_size; j++) {
        DEBUG(SSSDBG_CRIT_FAILURE, " denied_sids[%d] = %s\n", j,
              denied_sids[j]);
    }


    result = EOK;
    ret = prepare_response(main_ctx, result, allowed_size, allowed_sids, denied_size, denied_sids, &resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "prepare_response failed. [%d][%s].\n",
                    ret, strerror(ret));
        goto fail;
    }

    errno = 0;
    DEBUG(SSSDBG_TRACE_FUNC, "resp->size: %zu\n", resp->size);

    written = sss_atomic_write_s(STDOUT_FILENO, resp->buf, resp->size);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "write failed [%d][%s].\n", ret,
                    strerror(ret));
        goto fail;
    }

    if (written != resp->size) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Expected to write %zu bytes, wrote %zu\n",
              resp->size, written);
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "gpo_child completed successfully\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(0);

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "gpo_child failed!\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(-1);
}
