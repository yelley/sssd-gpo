/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef AD_GPO_H_
#define AD_GPO_H_

/*
 * This pair of functions provides client-side GPO processing.
 *
 * While a GPO can target both user and computer objects, this
 * implementation only supports targetting of computer objects.
 *
 * A GPO overview is at https://fedorahosted.org/sssd/wiki/GpoOverview
 *
 * In summary, client-side processing involves:
 * - determining the target's DN
 * - extracting the SOM object DNs (i.e. OUs and Domain) from target's DN
 * - including the target's Site as another SOM object
 * - determining which GPOs apply to the target's SOMs
 * - prioritizing GPOs based on SOM, link order, and whether GPO is "enforced"
 * - retrieving the corresponding GPO objects
 * - sending the GPO DNs to the CSE processing engine for policy application
 * - policy application currently consists of HBAC-like functionality
 */
struct tevent_req *
ad_gpo_access_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sss_domain_info *domain,
                       struct ad_access_ctx *ctx,
                       char *user);

errno_t ad_gpo_access_recv(struct tevent_req *req);

struct security_descriptor;

#endif /* AD_GPO_H_ */
