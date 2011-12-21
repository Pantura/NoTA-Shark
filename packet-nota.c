/* packet-nota.c
 * Routines for NoTA packet dissection
 *
 * Copyright 2010 Antti Palola <antti.palola@tut.fi>
 *
 * $Id:
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * See http://www.notaworld.org/ for more information
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
/*#include <epan/conversation.h>*/
#include <epan/prefs.h>
#include <string.h>

#include <epan/strutil.h>

static int proto_nota = -1;
static int proto_nota_high = -1;


/* Now added*/
static int hf_nota_ia_dst = -1;
static int hf_nota_ia_src = -1;
static int hf_nota_len_pl = -1;
static int hf_nota_ttl = -1;
static int hf_nota_id_pdu = -1;
static int hf_nota_id_prot = -1;
static int hf_nota_id_msg = -1;

static int hf_nota_IARP_message = -1;
static int hf_nota_PAP_message = -1;
static int hf_nota_CMP_message = -1;
static int hf_nota_GEN_message = -1;
static int hf_nota_USR_message = -1;


static int hf_t_lsockid = -1;
static int hf_t_ldsockid = -1;
static int hf_t_loffset = -1;

static int hf_t_lup_type = -1;
static int hf_t_ldtype_main = -1;
static int hf_t_ldtype_ext = -1;
static int hf_t_ldtype_ext_ip = -1;
static int hf_t_ldnetid = -1;

static int hf_t_lerror = -1;
static int hf_t_levent = -1;

static int hf_t_cookie = -1;

static int hf_t_ia_own = -1;
static int hf_t_ia_other = -1;

static int hf_pai_length = -1;

/*High interconnect fields */
static int hf_hsrc_ia = -1;
static int hf_hlen_pl = -1;
static int hf_hpdu_id = -1;
static int hf_hprot_id = -1;
static int hf_hmsg_id = -1;

static int hf_nota_high_SHP_message = -1;
static int hf_nota_high_SRP_message = -1;
static int hf_nota_high_SDP_message = -1;
static int hf_nota_high_SAP_message = -1;

static int hf_t_hrel_primary = -1;
static int hf_t_hrel_secondary = -1;
static int hf_t_hflags = -1;
static int hf_t_hmsg_len = -1;
static int hf_t_hstatus = -1;
static int hf_t_sid = -1;
static int hf_t_ia = -1;
static int hf_t_hsockid = -1;
static int hf_t_hportid = -1;
static int hf_high_sid_entries = -1;


static gint ett_nota = -1;
static gint ett_nota_LINup = -1;

static gint ett_nota_high = -1;
static gint ett_nota_high_msg = -1;
static gint ett_nota_high_sdp_cnf = -1;

/*TEST*/
static gint ett_nota_cmap_cnf = -1;

static dissector_handle_t nota_high_handle;
static dissector_handle_t data_handle;

#define DEFAULTnet_hostport 57852
/*static guint notaServerPort=DEFAULTnet_hostport;*/

#define COOKIE_LENGTH 2048

/* ----- NOTA SPECIFIC DEFINITIONS ---------*/
/* L_IN Protocol IDs */
#define IARP	0x01 /* Interconnect Address Resolution Protocol */
#define PAP		0x02 /* Peer Access Protocol */
#define CMP		0x03 /* Connectivity Map Protocol */
#define GEN		0x04 /* General Category */
#define USR		0xaa /* Data Plane Protocols */

static const value_string names_lin_prot_types[] = {
        { IARP, "Interconnect Address Resolution Protocol" },
        { PAP, "Peer Access Protocol" },
        { CMP, "Connectivity Map Protocol" },
		{ GEN, "General Category" },
		{ USR, "Data Plane Protocols" },
};


	/* GEN */
#define GEN_Echo_req	0x00
#define GEN_Echo_cnf	0x01
#define GEN_Info_req	0x02
#define GEN_Info_cnf	0x03
#define GEN_Error_ind	0x04
#define GEN_Event_ind	0x05
#define GEN_Authenticate_req 0x06
#define GEN_Authenticate_cnf 0x07

static const value_string names_gen_messages[] = {
        { GEN_Echo_req, "Echo request" },
        { GEN_Echo_cnf, "Echo confirm" },
        { GEN_Info_req, "Info request" },
		{ GEN_Info_cnf, "Info confirm" },
		{ GEN_Error_ind, "Error indication" },
		{ GEN_Event_ind, "Event indication" },
		{ GEN_Authenticate_req, "Authenticate request" },
		{ GEN_Authenticate_cnf, "Authenticate confirm" },
		{ 0, NULL },
};

	/* IARP */
#define IARP_GetIA_req	0x00
#define IARP_GetIA_cnf	0x01
#define IARP_ReleaseIA_req	0x02
#define IARP_ReleaseIA_cnf	0x03

static const value_string names_iarp_messages[] = {
        { IARP_GetIA_req, "Get IA req" },
        { IARP_GetIA_cnf, "Get IA cnf" },
        { IARP_ReleaseIA_req, "Release IA req" },
		{ IARP_ReleaseIA_cnf, "Release IA cnf" },
		{ 0, NULL },
};
	/* PAP */
#define PAP_Connect_req		0x00
#define PAP_Connect_cnf		0x01

static const value_string names_pap_messages[] = {
        { PAP_Connect_req, "Connect request" },
        { PAP_Connect_cnf, "Connect confirm" },
		{ 0, NULL },
};

	/* CMP */
#define CMP_GetCmap_req		0x00
#define CMP_GetCmap_cnf		0x01
#define CMP_GetCmap_ind		0x02

static const value_string names_cmp_messages[] = {
        { CMP_GetCmap_req, "Get Connectivity map request" },
        { CMP_GetCmap_cnf, "Get Connectivity map confirm" },
        { CMP_GetCmap_ind, "Get Connectivity map indication" },
		{ 0, NULL },
};

	/* USR */
#define USR_MessageCL_ind	0x00

static const value_string names_usr_messages[] = {
        { USR_MessageCL_ind, "User connectionless message indication" },
		{ 0, NULL },
};


/* H_IN Protocol IDs */
#define SHP				0x01	/* Subsystem Handshaking Protocol */
#define SRP				0x02	/* Service Registration Protocol */
#define SDP				0x03	/* Service Discovery Protocol */
#define SAP				0x04	/* Service Access Protocol */

static const value_string names_hin_prot_types[] = {
        { SHP, "Subsystem Handshaking Protocol" },
        { SRP, "Service Registration Protocol" },
        { SDP, "Service Discovery Protocol" },
		{ SAP, "Service Access Protocol" },
		{ 0, NULL },
};

/* H_IN message IDs */
	/*	SHP */
#define SHP_Handshake_req	0x01
#define SHP_Handshake_cnf	0x02
#define SHP_Echo_req		0x03
#define SHP_Echo_cnf		0x04

static const value_string names_shp_messages[] = {
        { SHP_Handshake_req, "Handshake request" },
        { SHP_Handshake_cnf, "Handshake confirm" },
        { SHP_Echo_req, "Echo request" },
		{ SHP_Echo_cnf, "Echo confirm" },
		{ 0, NULL },
};
	/* SRP */
#define SRP_ServiceActivate_req		0x01
#define SRP_ServiceActivate_cnf		0x02
#define SRP_ServiceDeactivate_req	0x03
#define SRP_ServiceDeactivate_cnf	0x04

static const value_string names_srp_messages[] = {
        { SRP_ServiceActivate_req, "Service activate request" },
        { SRP_ServiceActivate_cnf, "Service activate confirm" },
        { SRP_ServiceDeactivate_req, "Service deactivate request" },
		{ SRP_ServiceDeactivate_cnf, "Service deactivate confirm" },
		{ 0, NULL },
};

	/*SDP */
#define SDP_ServiceDiscovery_req	0x01
#define SDP_ServiceDiscovery_cnf	0x02

static const value_string names_sdp_messages[] = {
        { SDP_ServiceDiscovery_req, "Service discovery request" },
        { SDP_ServiceDiscovery_cnf, "Service discovery confirm" },
		{ 0, NULL },
};

	/* SAP */
#define SAP_ServiceAccess_req		0x01
#define SAP_ServiceAccess_cnf		0x02
#define SAP_AuthorizeAccess_req		0x05
#define SAP_AuthorizeAccess_cnf		0x06

static const value_string names_sap_messages[] = {
        { SAP_ServiceAccess_req, "Service access request" },
        { SAP_ServiceAccess_cnf, "Service access confirm" },
        { SAP_AuthorizeAccess_req, "Authorize access request" },
		{ SAP_AuthorizeAccess_cnf, "Authorize access request" },
		{ 0, NULL },
};

/* General Low Interconnect types and enumerations */
/* t_lstatus */
#define L_STATUS_OK		0
#define L_STATUS_DISCONNECTED	-1
#define L_STATUS_NOK		-2
#define L_STATUS_NOT_AVAILABLE	-3
#define L_STATUS_ABORTED	-4
#define L_STATUS_MESSAGE_TOO_LONG	-5
#define L_STATUS_BUSY		-6

/* t_ia */
#define IA_ANY	-1
#define IA_UNKNOWN	-2
#define IA_ANY_MNG	-3 /* Any manager IA. Used during IA resolution (IARP) */

static const value_string names_t_ia[] = {
        { IA_ANY, "Any" },
        { IA_UNKNOWN, "Unknown" },
        { IA_ANY_MNG, "Any Manager IA" },
		{ 0, NULL },
};

/* t_lsockid */
#define L_SOCKID_ANY	-1
#define L_SOCKID_ERROR	-2

static const value_string names_t_lsockid[] = {
        { L_SOCKID_ANY, "Any" },
        { L_SOCKID_ERROR, "Error" },
		{ 0, NULL },
};
/* t_lsocktype */
#define L_SOCKTYPE_NA	0 /* Unknown socket type */
#define L_SOCKTYPE_CL	1 /* Connectionless socket */
#define L_SOCKTYPE_CO	2 /* Connection-oriented socket */

/* t_ldsockid */
#define LD_SOCKID_ANY	-1 /* Used for opening any free L_INdown socket */
#define LD_SOCKID_ERROR	-2 /* Socket operation failed */
#define LD_SOCKID_NA	-3 /* Socket not available */

static const value_string names_t_ldsockid[] = {
        { LD_SOCKID_ANY, "Any" },
        { LD_SOCKID_ERROR, "Error" },
		{ LD_SOCKID_NA, "Not available"},
		{ 0, NULL },
};

/* t_luptype */
#define LUPTYPE_UNKNOWN	0x00000000	/* Unknown LupType */
#define LUPTYPE_BN		0x00000001	/* L_INup basic capability */
#define LUPTYPE_MNG		0x00000002	/* L_INup manager capability */
#define LUPTYPE_GW		0x00000004	/* L_INup gateway capability */
#define LUPTYPE_ANY		0xFFFFFFFF

static const value_string names_t_luptype[] = {
        { LUPTYPE_UNKNOWN, "Unknown LupType" },
        { LUPTYPE_BN, "L_INup basic capability" },
        { LUPTYPE_MNG, "L_INup manager capability" },
		{ LUPTYPE_GW, "L_INup gateway capability" },
		{ LUPTYPE_ANY, "Any" },
		{ 0, NULL},
};

/* t_ldstatus */
#define LD_STATUS_OK	-1	/*Success*/
#define LD_STATUS_NOK	-2	/* Failure */
#define LD_STATUS_DISCONNECTED	-3
#define LD_STATUS_NOT_AVAILABLE -4
#define LD_STATUS_TOO_LONG		-5
#define L_STATUS_PEER_ACTIVATED -6 /* Disconnected with reason */
#define L_STATUS_UNKNOWN		-7 /* Disconnected with reason */

static const value_string names_t_ldstatus[] = {
        { LD_STATUS_OK, "Success" },
        { LD_STATUS_NOK, "Failure" },
        { LD_STATUS_DISCONNECTED, "Disconnected" },
		{ LD_STATUS_NOT_AVAILABLE, "Not available" },
		{ LD_STATUS_TOO_LONG, "Too long" },
		{ L_STATUS_PEER_ACTIVATED, "Peer activated" },
		{ L_STATUS_UNKNOWN, "Unknown" },
		{ 0, NULL},
};

/* t_ldsocktype */
#define LD_SOCKTYPE_NA	0 /* Unknown socket type */
#define LD_SOCKTYPE_CL	1 /* Connectionless socket */
#define LD_SOCKTYPE_CO	2 /* Connection-oriented socket */

/* t_ldnetid */
#define LD_NETID_ANY	0 /* For CMP_GetCmap_req() mask purposes */
#define LD_NETID_UNKNOWN 0 /* Unknown network ID */
/* t_ldmsgid */
#define LD_MSGID_NA		0	 /* Not supported */

/* t_lerror */
#define ERR_GENERAL		1
#define ERR_UNKNOWN_PDU 2
#define ERR_UNKNOWN_IA	3
#define ERR_UNKNOWN_LSOCKID	4
#define ERR_TIMEOUT		5
#define ERR_PDU_SIZE_EXCEEDED	6

static const value_string names_t_lerror[] = {
        { ERR_GENERAL, "General Error" },
        { ERR_UNKNOWN_PDU, "Unknown PDU" },
        { ERR_UNKNOWN_IA, "Unknown IA" },
		{ ERR_UNKNOWN_LSOCKID, "Unknown LSocket ID" },
		{ ERR_TIMEOUT, "Timeout" },
		{ ERR_PDU_SIZE_EXCEEDED, "PDU size exceeded" },
		{ 0, NULL},
};

/* t_levent */
#define L_EVENT_MNG_IA_CHANGED	1	/* Indication about L_INup manager node IA change. */
#define L_EVENT_SUBSYST_RESET	2	/* Request to perform sub-system hard reset. */

static const value_string names_t_levent[] = {
        { L_EVENT_MNG_IA_CHANGED, "L_INup manager node IA changed" },
        { L_EVENT_SUBSYST_RESET, "Perform sub-system hard reset" },
   		{ 0, NULL},
};

/* LD-types: MAIN and EXT */
#define LD_TYPE_MAIN_ANY          0xffffffff
#define LD_TYPE_EXT_ANY           0xffffffff

#define LD_TYPE_MAIN_UNKNOWN      0x00000000
#define LD_TYPE_EXT_UNKNOWN       0x00000000

#define LD_TYPE_MAIN_DUMMY        0x00000001
#define LD_TYPE_EXT_DUMMY_DUMMY   0x00000001

#define LD_TYPE_MAIN_SIMPLE       0x00000002
#define LD_TYPE_EXT_SIMPLE_SIMPLE 0x00000002

#define LD_TYPE_MAIN_IP           0x00002000
#define LD_TYPE_EXT_IP_TCP        0x00000001
#define LD_TYPE_EXT_IP_UDP        0x00000002
#define LD_TYPE_EXT_IP_TCP_UDP    0x00000004
#define LD_TYPE_EXT_IP_TCP_NO_UDP 0x00000008       /* new ld_tcp_ip UDP removed */

#define LD_TYPE_MAIN_USB          0x00003000
#define LD_TYPE_EXT_USB_10LS      0x00000001
#define LD_TYPE_EXT_USB_10FS      0x00000002
#define LD_TYPE_EXT_USB_20HS      0x00000004
#define LD_TYPE_EXT_USB_OTG       0x00000008

#define LD_TYPE_MAIN_BT           0x00004000
#define LD_TYPE_EXT_BT_20EDR      0x00000001
#define LD_TYPE_EXT_BT_21EDR      0x00000002
#define LD_TYPE_EXT_BT_RFCOMM     0x00000004      /* new ld_bt_rfcomm */

#define LD_TYPE_MAIN_SINGLE       0x00005000
#define LD_TYPE_EXT_SINGLE_SINGLE 0x00005000

#define LD_TYPE_MAIN_EXAMPLE        0x00006000
#define LD_TYPE_EXT_EXAMPLE_EXAMPLE 0x00006000

static const value_string names_t_ldtype_main[] = {
        { LD_TYPE_MAIN_ANY, "Any" },
        { LD_TYPE_MAIN_UNKNOWN, "Unknown" },
        { LD_TYPE_MAIN_DUMMY, "Dummy" },
		{ LD_TYPE_MAIN_SIMPLE, "Simple" },
		{ LD_TYPE_MAIN_IP, "IP" },
		{ LD_TYPE_MAIN_USB, "USB" },
		{ LD_TYPE_MAIN_BT, "Bluetooth" },
		{ LD_TYPE_MAIN_SINGLE, "Single" },
		{ LD_TYPE_MAIN_EXAMPLE, "Example" },
		{ 0, NULL },
};

static const value_string names_t_ldtype_ext_ip[] = {
        { LD_TYPE_EXT_ANY, "Any" },
        { LD_TYPE_EXT_IP_TCP, "IP with TCP" },
        { LD_TYPE_EXT_IP_UDP, "IP with UDP" },
		{ LD_TYPE_EXT_IP_TCP_UDP, "IP with TCP and UDP" },
		{ LD_TYPE_EXT_IP_TCP_NO_UDP, "IP with TCP no UDP" },
		{ 0, NULL},
};


/* ----H_IN Definitions & Enumerations -----------*/
/*t_hstatus*/
#define H_STATUS_OK 0
#define H_STATUS_NOK 1
#define H_STATUS_NOT_MNG 2
#define H_STATUS_NOT_PERMITTED 3
#define H_STATUS_NOT_FOUND 4

static const value_string names_t_hstatus[] = {
        { H_STATUS_OK, "OK" },
        { H_STATUS_NOK, "not OK" }, /*general error */
        { H_STATUS_NOT_MNG, "Not manager" },
		{ H_STATUS_NOT_PERMITTED, "Not permitted" },
		{ H_STATUS_NOT_FOUND, "Not found" },
		{ 0, NULL},
};

/*t_hsocktype*/
#define H_SOCKTYPE_MSG 	0x0001
#define H_SOCKTYPE_STREAM 0x0002

static const value_string names_t_hsocktype[] = {
        { H_SOCKTYPE_MSG, "Message type socket" },
        { H_SOCKTYPE_STREAM, "Streaming type socket" },
		{ 0, NULL},
};

/*t_hmngstatus*/
#define HMNG_STATUS_ACCEPT 0x0000
#define HMNG_STATUS_ACCEPT_WITH_SEC 0x0001
#define HMNG_STATUS_DENY 0x0002

static const value_string names_t_hmngstatus[] = {
        { HMNG_STATUS_ACCEPT, "Accept request" },
        { HMNG_STATUS_ACCEPT_WITH_SEC, "Access needs to be authorized via manager H_IN" }, /*general error */
        { HMNG_STATUS_DENY, "Deny request" },
		{ 0, NULL},
};

/*t_hpolicy*/
#define H_POLICY_ACCEPT_ALL 0x0000
#define H_POLICY_VALIDATE 0x0001

#define H_SID_ANY 0xffffffff

static const value_string names_t_sid[] = {
        { H_SID_ANY, "Any SID" },
		{ 0, NULL},
};

/*c_hmsg*/
/*	hmsg_len (uint16)
	msg_body(8bit*len)
*/


static gboolean dissect_nota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


static int
dissect_nota_IARP
(tvbuff_t *tvb, proto_tree *tree)
{
	int offset;
	
	guint8 nota_id_msg = 0;
	guint32 nota_lup_type = 0;
	
	int length;
	gchar cookie[COOKIE_LENGTH+1];
 	gchar *cookie_ptr = cookie;

	offset = 0;

	if (tree) {
		
		
		nota_id_msg = tvb_get_guint8(tvb, offset);
		
		proto_tree_add_item(tree, hf_nota_IARP_message, tvb,
			offset, 1, nota_id_msg);
		offset ++;/* offset 2 as the next byte is reserved */
		
		proto_tree_add_item(tree, hf_nota_len_pl, tvb,
			offset, 2, TRUE);
		offset += 2;
		
		
		/*
		IARP_GetIA_req	0x00
		IARP_GetIA_cnf	0x01
		IARP_ReleaseIA_req	0x02
		IARP_ReleaseIA_cnf	0x03
		*/
		switch(nota_id_msg){
			case IARP_GetIA_req:
				/*lup_type(uint32), cookie;*/
				nota_lup_type = tvb_get_ntohl(tvb, offset);
				proto_tree_add_item(tree, hf_t_lup_type, tvb,
					offset, 4, nota_lup_type);
				offset += 4;
				
				/*read the rest into cookie*/
				length = tvb_reported_length(tvb) - offset;
				/*cookie_ptr = tvb_get_seasonal_string(tvb, offset, length);*/
				cookie_ptr = tvb_bytes_to_str(tvb, offset, length);
/*				length = tvb_get_nstringz0(tvb, offset, sizeof(cookie), cookie);*/
/*				proto_tree_add_item(tree, hf_t_cookie, tvb, offset, length, cookie);*/
				proto_tree_add_string(tree, hf_t_cookie,
						  tvb, offset, length, cookie_ptr);
				offset += length;
			break;
			case IARP_GetIA_cnf:
				/*IA own, L_INmng IA*/
				proto_tree_add_item(tree, hf_t_ia_own, tvb,
					offset, 4,TRUE);
				offset += 4;
				proto_tree_add_item(tree, hf_t_ia_other, tvb,
					offset, 4, TRUE);
				offset += 4;
			break;
			case IARP_ReleaseIA_req:
				/*IA own, cookie*/
				proto_tree_add_item(tree, hf_t_ia_own, tvb,
					offset, 4, TRUE);
				offset += 4;
				/*read the rest into cookie?*/
				length = tvb_reported_length(tvb) - offset;
				cookie_ptr = tvb_bytes_to_str(tvb, offset, length);
				proto_tree_add_string(tree, hf_t_cookie,
						  tvb, offset, length, cookie_ptr);
				offset += length;
			break;
			case IARP_ReleaseIA_cnf:
				/*No payload?*/
			break;
			default:
				/*Wrong msg ID, what to do?*/
			break;
		}

	}
	return offset;
}

static int
dissect_nota_PAP
(tvbuff_t *tvb, proto_tree *tree)
{
	int offset;
	guint8 nota_id_msg = 0;
	
	int length;
	gchar cookie[COOKIE_LENGTH+1];
 	gchar *cookie_ptr = cookie;

	offset = 0;

	if (tree) {
			
		nota_id_msg = tvb_get_guint8(tvb, offset);
		
		proto_tree_add_item(tree, hf_nota_PAP_message, tvb,
			offset, 1, nota_id_msg);
		offset++;
		proto_tree_add_item(tree, hf_nota_len_pl, tvb,
			offset, 2, TRUE);
		offset += 2;
		
		
		/*
		PAP_Connect_req		0x00q
		PAP_Connect_cnf		0x01
		*/
		switch(nota_id_msg){
			case PAP_Connect_req:
				/*t_lsockid, t_loffset, t_cookie;*/
				/*Notice in req socket ID is for LINup and in cnf for LINdown */
				proto_tree_add_item(tree, hf_t_lsockid, tvb,
					offset, 4,TRUE);
				offset += 4;
				proto_tree_add_item(tree, hf_t_loffset, tvb,
					offset, 8, TRUE);
				offset += 8;
				/*read the rest into cookie*/
				length = tvb_reported_length(tvb) - offset;
				cookie_ptr = tvb_bytes_to_str(tvb, offset, length);
				proto_tree_add_string(tree, hf_t_cookie,
						  tvb, offset, length, cookie_ptr);
				offset += length;
			break;
			
			case PAP_Connect_cnf:
				/*t_ldsockid, t_loffset, t_cookie;*/
				/*Notice in req socket ID is for LINup and in cnf for LINdown */
				proto_tree_add_item(tree, hf_t_ldsockid, tvb,
					offset, 4,TRUE);
				offset += 4;
				proto_tree_add_item(tree, hf_t_loffset, tvb,
					offset, 8, TRUE);
				offset += 8;	
				/*read the rest into cookie*/
				length = tvb_reported_length(tvb) - offset;
				cookie_ptr = tvb_bytes_to_str(tvb, offset, length);
				proto_tree_add_string(tree, hf_t_cookie,
						  tvb, offset, length, cookie_ptr);
				offset += length;
			break;
			
			default:
				/*Wrong msg ID, what to do?*/
			break;
		}

	}
	return offset;
}


static int
dissect_nota_CMP
(tvbuff_t *tvb, proto_tree *tree)
{
	int 	offset;
	int		old_offset;
	unsigned int 	node_no;
	guint8 nota_id_msg = 0;
	guint16 length;
	guint16 pai_length;
	
	proto_item *cmap_cnf_item;
	proto_tree *cmap_cnf_tree;
	proto_item *cmap_item;
	proto_tree *cmap_tree;
	
/*	tvbuff_t	*next_tvb;*/

	gint	rest_length;
	
	offset = 0;
	old_offset = 0;
	node_no = 1;

	if (tree) {
		
		nota_id_msg = tvb_get_guint8(tvb, offset);
		
		proto_tree_add_item(tree, hf_nota_CMP_message, tvb,
			offset, 1, nota_id_msg);
		offset++;
		
		length = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tree, hf_nota_len_pl, tvb,
			offset, 2, length);
		offset += 2;
		
		
		/*
		#define CMP_GetCmap_req		0x00
		#define CMP_GetCmap_cnf		0x01
		#define CMP_GetCmap_ind		0x02
		*/
		switch(nota_id_msg){
			case CMP_GetCmap_req:
				/*t_ia, t_luptype, t_ldtype_main, t_ldtype_ext, t_ldnetid;*/
				proto_tree_add_item(tree, hf_t_ia_other, tvb,
					offset, 4,TRUE);
				offset += 4;
				proto_tree_add_item(tree, hf_t_lup_type, tvb,
					offset, 4, TRUE);
				offset += 4;
				proto_tree_add_item(tree, hf_t_ldtype_main, tvb,
					offset, 4, TRUE);
				offset += 4;
				/*check which main transport type was used to determine
				correct external type list */
				if (tvb_get_ntohs(tvb, offset - 4) == LD_TYPE_MAIN_IP){
					proto_tree_add_item(tree, hf_t_ldtype_ext_ip, tvb,
						offset, 4, TRUE);
				}
				else{
					proto_tree_add_item(tree, hf_t_ldtype_ext_ip, tvb,
						offset, 4, TRUE);
				}
				
				offset += 4;
				proto_tree_add_item(tree, hf_t_ldnetid, tvb,
					offset, 4, TRUE);
				offset += 4;
			break;
			
			case CMP_GetCmap_cnf:
				/*t_ia, t_luptype, t_ldtype_main, t_ldtype_ext, t_pai,
					t_ldnetid, +N*first 6 fields */
					/*loop through data */
				cmap_item = proto_tree_add_text(tree, tvb, offset, -1, "Connectivity map nodes");
				cmap_tree = proto_item_add_subtree(cmap_item, ett_nota);
					
				rest_length = tvb_reported_length(tvb) - offset;
					do {
						cmap_cnf_item = proto_tree_add_text(cmap_tree, tvb, offset, -1, "Node %u (%u bytes of payload left)", 
							node_no, rest_length);

						/* cmap_item <> cmap_cnf_item */
						cmap_cnf_tree = proto_item_add_subtree(cmap_cnf_item, ett_nota_cmap_cnf);
						
						proto_tree_add_item(cmap_cnf_tree, hf_t_ia_other, tvb,
							offset, 4, TRUE);
						offset += 4;
						proto_tree_add_item(cmap_cnf_tree, hf_t_lup_type, tvb,
							offset, 4, TRUE);
						offset+= 4;
						proto_tree_add_item(cmap_cnf_tree, hf_t_ldtype_main, tvb,
							offset, 4, TRUE);
						offset += 4;
						
						//For some reason this doesn't seem to be true ever
						if (tvb_get_ntohs(tvb, offset - 4) == LD_TYPE_MAIN_IP){
							proto_tree_add_item(cmap_cnf_tree, hf_t_ldtype_ext_ip, tvb,
								offset, 4, TRUE);
						}
						else{
							proto_tree_add_item(cmap_cnf_tree, hf_t_ldtype_ext, tvb,
								offset, 4, TRUE);
						}
						offset += 4;

						/*dissect t_pai*/ 
						pai_length = tvb_get_letohs(tvb, offset);
						proto_tree_add_item(cmap_cnf_tree, hf_pai_length, tvb,
							offset, 2, pai_length);
						offset += pai_length + 2;

						/* /dissect_t_pai*/ 

						proto_tree_add_item(cmap_cnf_tree, hf_t_ldnetid, tvb,
							offset, 4, TRUE);
						offset += 4;
						
						rest_length -= (offset - old_offset);
						
						node_no ++;
						old_offset = offset;

					} while(rest_length > 0);
					
									
			break;
			
			case CMP_GetCmap_ind:
				/*payload?*/			
			break;
			
			default:
				/*Wrong msg ID, what to do?*/
			break;
		}

	}
	return offset;
}


static int
dissect_nota_GEN
(tvbuff_t *tvb, proto_tree *tree)
{
	int 		offset;
/*	proto_item 	*ti;Ä*/
	guint8 		nota_id_msg = 0;
/*	guint rest_length = 0;*/
	
	guint16		primary_version = 0;
	guint16		secondary_version = 0;
	
	guint32 	t_lerror;
	guint32 	t_levent;
	
	

	offset = 0;

	if (tree) {
		
		nota_id_msg = tvb_get_guint8(tvb, offset);
		
		proto_tree_add_item(tree, hf_nota_GEN_message, tvb,
			offset, 1, nota_id_msg);
		offset++;
		proto_tree_add_item(tree, hf_nota_len_pl, tvb,
			offset, 2, TRUE);
		offset += 2;
		
		
		/*
		#define GEN_Echo_req	0x00
		#define GEN_Echo_rcnf	0x01
		#define GEN_Info_req	0x02
		#define GEN_Info_cnf	0x03
		#define GEN_Error_ind	0x04
		#define GEN_Event_ind	0x05
		#define GEN_Authenticate_req 0x06
		#define GEN_Authenticate_cnf 0x07
		*/
		switch(nota_id_msg){
			case GEN_Echo_req:
				/*N bytes, print the rest of the packet
				might need to call data_dissector for this data*/
			/*	rest_length = tvb_reported_length(tvb) - 1;
				proto_tree_add_item(tree, hf_echo_item, tvb,
					offset, rest_length, TRUE);
				offset += rest_length;*/
			break;
			case GEN_Echo_cnf:
				/*N bytes, print the rest of the packet*/
			/*	rest_length = tvb_reported_length(tvb) - 1;
				proto_tree_add_item(tree, hf_echo_item, tvb,
					offset, rest_length, TRUE);
				offset += rest_length;			*/	
			break;
			case GEN_Info_req:
				/*no payload, just name it*/
			break;
			case GEN_Info_cnf:
				/*read 2 16 bit version fields*/
				primary_version = tvb_get_ntohs(tvb, offset);
				secondary_version = tvb_get_ntohs(tvb, offset + 2 );
				offset += 4;
				/*offset changed from 0 */
				proto_tree_add_text(tree, tvb, offset, -1, "Version: %u.%u",
				primary_version, secondary_version);
			break;
			case GEN_Error_ind:
				/*t_lerror()*/
				t_lerror = tvb_get_ntohl(tvb, offset);
				/* Decode error to text */
				
			
			break;
			case GEN_Event_ind:
				/*t_levent, t_cookie*/
				t_levent = tvb_get_ntohl(tvb, offset);
				/* decode event to text */
				
			break;
			case GEN_Authenticate_req:
				/*t_msg*/
				/*print string or hex ? */
			break;
			case GEN_Authenticate_cnf:
				/*t_msg*/
			break;
			default:
				/*Wrong msg ID, what to do?*/
			break;
		}

	}
	return offset;
}

static int
dissect_nota_USR
(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *main_tree)
{
	int 		offset;
	
	guint8 		nota_id_msg = 0;
	guint16		nota_len_pl = 0;

	tvbuff_t	*next_tvb;
	int			rest_length;
	
	offset = 0;

	if (tree) {
		
		nota_id_msg = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_nota_USR_message, tvb,
			offset, 1, nota_id_msg);
		offset++;	
		
		nota_len_pl = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_nota_len_pl, tvb,
			offset, 2, nota_len_pl);
		offset += 2;
		
		/*
		#define USR_MessageCL_ind	0x00
		*/
		switch(nota_id_msg){
			case USR_MessageCL_ind:
				/*2x t_lsockid(int32) + N*uint8 message */
				proto_tree_add_item(tree, hf_t_lsockid, tvb,
					offset, 4, TRUE);
				offset += 4;
				proto_tree_add_item(tree, hf_t_lsockid, tvb,
					offset, 4, TRUE);
				offset += 4;
					
				/* In final case this data is sent to H_IN dissector */
	
				rest_length = tvb_reported_length(tvb) - offset;
				
				next_tvb = tvb_new_subset(tvb, offset, rest_length , rest_length);
				call_dissector(nota_high_handle, next_tvb, pinfo, main_tree);
			break;
			
			default:
				/*Wrong msg ID, what to do?*/
			break;
		}

	}
	return offset;
}

static int dissect_nota_high_SHP(tvbuff_t *tvb, proto_tree *tree)
{
	guint16		hmsg_id;
	int offset = 0;
	
	
	if(tree){
		hmsg_id = tvb_get_letohs(tvb, 0);
		proto_tree_add_item(tree, hf_nota_high_SHP_message, tvb, 0, 2, TRUE);
	
		/*#define SHP_Handshake_req	0x01
		#define SHP_Handshake_cnf	0x02
		#define SHP_Echo_req		0x03
		#define SHP_Echo_cnf		0x04
		*/
		switch(hmsg_id){
			case SHP_Handshake_req:
				/*t_hrel(uns8) x2, t_hflags(uns16), c_hmsg*/
				/*chmsg = 16 byte lenght + data */
				proto_tree_add_item(tree, hf_t_hrel_primary, tvb, 2, 1, TRUE);
				proto_tree_add_item(tree, hf_t_hrel_secondary, tvb, 3, 1, TRUE);
				proto_tree_add_item(tree, hf_t_hflags, tvb, 4, 2, TRUE);
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 6, 2, TRUE);
				/*Anything else optional so far */
			break;
			case SHP_Handshake_cnf:
				/*t_hrel x2, t_hflags, t_hstatus(uns16), c_hmsg*/
				proto_tree_add_item(tree, hf_t_hrel_primary, tvb, 2, 1, TRUE);
				proto_tree_add_item(tree, hf_t_hrel_secondary, tvb, 3, 1, TRUE);
				proto_tree_add_item(tree, hf_t_hflags, tvb, 4, 2, TRUE);
				proto_tree_add_item(tree, hf_t_hstatus, tvb, 6, 2, TRUE);
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 8, 2, TRUE);
			break;
			case SHP_Echo_req:
				/*c_hmsg*/
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 2, 2, TRUE);
				/*message to echo*/
			break;
			case SHP_Echo_cnf:
				/*c_hmsg*/
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 2, 2, TRUE);
			break;
			default:
			/*do nothing*/
			break;
		}
		
	}
	return offset;
}

static int dissect_nota_high_SRP(tvbuff_t *tvb, proto_tree *tree)
{
	int offset = 0;
	guint16		hmsg_id;
	
	if(tree){
		
		hmsg_id = tvb_get_letohs(tvb, 0);
		proto_tree_add_item(tree, hf_nota_high_SRP_message, tvb, 0, 2, TRUE);
		/*#define SRP_ServiceActivate_req		0x01
		#define SRP_ServiceActivate_cnf		0x02
		#define SRP_ServiceDeactivate_req	0x03
		#define SRP_ServiceDeactivate_cnf	0x04*/
		
		switch(hmsg_id){
			case SRP_ServiceActivate_req:
				/*t_sid(uns32), c_hmsg(certificate optional)*/
				proto_tree_add_item(tree, hf_t_sid, tvb, 2, 4, TRUE);
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 6, 2, TRUE);
				/*Anything else optional so far */
			break;
			case SRP_ServiceActivate_cnf:
				/*t_hstatus(uns16), t_hflags*/
				proto_tree_add_item(tree, hf_t_hstatus, tvb, 2, 2, TRUE);
				proto_tree_add_item(tree, hf_t_hflags, tvb, 4, 2, TRUE);
			break;
			case SRP_ServiceDeactivate_req:
				/*t_sid, c_hmsg(optional certificate)*/
				proto_tree_add_item(tree, hf_t_sid, tvb, 2, 4, TRUE);
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 6, 2, TRUE);
				/*optional*/
			break;
			case SRP_ServiceDeactivate_cnf:
				/*t_hstatus*/
				proto_tree_add_item(tree, hf_t_hstatus, tvb, 2, 2, TRUE);
			break;
			default:
			/*do nothing*/
			break;
		}
	}
	return offset;
}

static int dissect_nota_high_SDP(tvbuff_t *tvb, proto_tree *tree)
{
	guint16		hmsg_id;
	guint16		sid_ia_pairs;
	guint16 	pair;
	int			offset = 0;
	
	proto_item *sdp_cnf_item;
	proto_tree *sdp_cnf_tree;
	proto_item *sdp_item;
	proto_tree *sdp_tree;


	if(tree){
		hmsg_id = tvb_get_letohs(tvb, 0);
		proto_tree_add_item(tree, hf_nota_high_SDP_message, tvb, 0, 2, TRUE);
		/*#define SDP_ServiceDiscovery_req	0x01
		#define SDP_ServiceDiscovery_cnf	0x02*/
		
		switch(hmsg_id){
			case SDP_ServiceDiscovery_req:
				/*t_sid(uns32), c_hmsg(certificate optional)*/
				proto_tree_add_item(tree, hf_t_sid, tvb, 2, 4, TRUE);
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 6, 2, TRUE);
				/*Anything else optional so far */
			break;
			case SDP_ServiceDiscovery_cnf:
				/*t_hstatus(uns16), number of sid entries(uns16), number*c_sid_ia */
				/*c_sid_ia (t_sid + t_ia -pair uns32+uns32bit ) */
				proto_tree_add_item(tree, hf_t_hstatus, tvb, 2, 2, TRUE);
				sid_ia_pairs = tvb_get_letohs(tvb, 4);
				
				proto_tree_add_item(tree, hf_high_sid_entries, tvb, 4, 2, TRUE);
				offset += 6;
				
				sdp_item = proto_tree_add_text(tree, tvb, offset, -1, "SID-IA pairs");
				sdp_tree = proto_item_add_subtree(sdp_item, ett_nota_high);
				
				/*Tree for these entries like in connectivity map cnf in L_IN */
				for(pair = 1; pair <= sid_ia_pairs; pair++){
					sdp_cnf_item = proto_tree_add_text(sdp_tree, tvb, offset, -1, "Pair %u", 
						pair);

					/* sdp_item <> sdp_cnf_item */
					sdp_cnf_tree = proto_item_add_subtree(sdp_cnf_item, ett_nota_high_sdp_cnf);
					
					proto_tree_add_item(sdp_cnf_tree, hf_t_sid, tvb,
						offset, 4, TRUE);
					offset += 4;
					proto_tree_add_item(sdp_cnf_tree, hf_t_ia, tvb,
						offset, 4, TRUE);
					offset += 4;
				}
				
			break;
			
			default:
			/*do nothing*/
			break;
		}
	}
	return offset;
}
static int dissect_nota_high_SAP(tvbuff_t *tvb, proto_tree *tree)
{
	guint16		hmsg_id;
	int offset = 0;
	
	if(tree){
		hmsg_id = tvb_get_letohs(tvb, 0);
		
		proto_tree_add_item(tree, hf_nota_high_SAP_message, tvb, 0, 2, TRUE);
		/*#define SAP_ServiceAccess_req		0x01
		#define SAP_ServiceAccess_cnf		0x02
		#define SAP_AuthorizeAccess_req		0x05
		#define SAP_AuthorizeAccess_cnf		0x06*/
		
		switch(hmsg_id){
			case SAP_ServiceAccess_req:
				/*t_sid(uns32), t_hportid(uns32), t_hflags(bit 0 streaming/message
				type connection), c_hmsg(certificate optional)*/
				proto_tree_add_item(tree, hf_t_sid, tvb, 2, 4, TRUE);
				proto_tree_add_item(tree, hf_t_hportid, tvb, 6, 4, TRUE);			
				proto_tree_add_item(tree, hf_t_hflags, tvb, 10, 2, TRUE);
				/*check the flags separately*/
				
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 12, 2, TRUE);
				/*Anything else optional so far */
			break;
			case SAP_ServiceAccess_cnf:
				/*t_hsockid(uns32), t_hstatus(uns16)*/
				proto_tree_add_item(tree, hf_t_hsockid, tvb, 2, 4, TRUE);
				proto_tree_add_item(tree, hf_t_hstatus, tvb, 6, 2, TRUE);
			break;
			case SAP_AuthorizeAccess_req:
				/*t_ia, t_sid, c_hmsg(optional certificate)*/
				proto_tree_add_item(tree, hf_t_ia, tvb, 2, 4, TRUE);
				proto_tree_add_item(tree, hf_t_sid, tvb, 6, 4, TRUE);
				proto_tree_add_item(tree, hf_t_hmsg_len, tvb, 10, 2, TRUE);
				/*optional*/
			break;
			case SAP_AuthorizeAccess_cnf:
				/*t_hstatus*/
				proto_tree_add_item(tree, hf_t_hstatus, tvb, 2, 2, TRUE);
			break;
			default:
			/*hms_id was wrong, need to inform?*/
			break;
		}
		
	}
	return offset;
}

/* -------------------------------------------*/
static void
dissect_nota_high(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*nota_high_tree = NULL;

	/* NOTA H_IN control place protocol common PDU format */
	/*CTRL_MESSAGE_PDU
	Field	Name		Format Description
	1.		ia_src 		t_ia	Source sub-system IA5
	2.		len_pl 		uns16	Payload length in bytes
	3.		hpdu_id 	uns16	H_IN specific unique PDU ID (i.e. sequence number)
	4.		hprot_id 	uns16	H_IN control plane protocol ID
	5.		hmsg_id 	uns16	Protocol specific message ID
	6.		payload 	any		Payload according to the protocol ID and PDU ID
	*/
/*	gint32 		ia_src = 0;
	guint16		len_pl = 0;
	guint16		hpdu_id = 0;*/
	guint16		hprot_id = 0;
	guint16		hmsg_id = 0;
	
	
	int 		offset = 0;
	int			rest_length = 0;
	
	tvbuff_t	*next_tvb;
	
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NoTA H_IN");
	col_clear(pinfo->cinfo, COL_INFO);
	
	
	if (tree) {
		proto_item *nota_high_item;

		nota_high_item = proto_tree_add_protocol_format(tree, proto_nota_high, tvb, 0, -1,
			"Network on Terminal Architecture, High Interconnect");
		nota_high_tree = proto_item_add_subtree(nota_high_item, ett_nota_high);
		
		col_append_fstr(pinfo->cinfo, COL_INFO, "Source IA: %x", tvb_get_letohl(tvb, offset) );
	}
	
	if(nota_high_tree){
		proto_tree_add_item(nota_high_tree, hf_hsrc_ia, tvb,
			offset, 4, TRUE);
		offset += 4;
		proto_tree_add_item(nota_high_tree, hf_hlen_pl, tvb,
			offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(nota_high_tree, hf_hpdu_id, tvb,
			offset, 2, TRUE);
		offset +=2;		
	}
	
	if(nota_high_tree){
		proto_item 	*HINup_item;
		proto_tree 	*HINmsg_tree;
		
		hprot_id = tvb_get_letohs(tvb, 8);
		hmsg_id = tvb_get_letohs(tvb, 10);
		
	
		HINup_item = proto_tree_add_text(nota_high_tree, tvb, offset + 2, -1, "Protocol: %s(%x)", 
			val_to_str(hprot_id, names_hin_prot_types, "%u"), hprot_id);

		HINmsg_tree = proto_item_add_subtree(HINup_item, ett_nota_high_msg);
		
		rest_length = tvb_reported_length(tvb) - 10;
		next_tvb = tvb_new_subset(tvb, 10, rest_length , rest_length);
		
		/*Switch-case for different H_IN protocol types */
		switch(hprot_id){
			case  SHP:
				col_append_fstr(pinfo->cinfo, COL_INFO, ", SHP-> %s",
			    	val_to_str(hmsg_id, names_shp_messages, "Unknown type"));
				dissect_nota_high_SHP(next_tvb, HINmsg_tree);
			break;
			case SRP:
				col_append_fstr(pinfo->cinfo, COL_INFO, ", SRP-> %s",
			    	val_to_str(hmsg_id, names_srp_messages, "Unknown type"));
				dissect_nota_high_SRP(next_tvb, HINmsg_tree);
			break;
			case SDP:
				col_append_fstr(pinfo->cinfo, COL_INFO, ", SDP-> %s",
			    	val_to_str(hmsg_id, names_sdp_messages, "Unknown type"));
				dissect_nota_high_SDP(next_tvb, HINmsg_tree);
			break;
			case SAP:
				col_append_fstr(pinfo->cinfo, COL_INFO, ", SAP-> %s",
			    	val_to_str(hmsg_id, names_sap_messages, "Unknown type"));
				dissect_nota_high_SAP(next_tvb, HINmsg_tree);
			break;
			default:
				/*otherwise it's streaming or message PDU, just send it to data */
				call_dissector(data_handle,next_tvb, pinfo, nota_high_tree);
		
			break;
		}
	
	
	}
		
}


static gboolean
dissect_nota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*nota_tree = NULL;	
	
	gint32		ia_dst = 0;
	gint32		ia_src = 0;
	guint8		nota_ttl = 0;
	guint16		nota_id_pdu = 0;
	guint8		nota_id_prot = 0;
	guint8		nota_id_msg	= 0;
	guint16		nota_len_pl = 0;
	
	guint		rest_length;
	tvbuff_t	*next_tvb;
	
	int offset = 0;
	
	/* Heuristic checks: 
		-see if there is enough data to make a NoTA-packet */
	if(tvb_reported_length(tvb) < 16){
		return FALSE;
	}
	/*9th byte is unused so it should be 0 */
	if(tvb_get_guint8(tvb, offset + 9) != 0){
		return FALSE;
	}
	
	/*proto id and msg id checks */
	/*nota_id_prot should not be bigger than 0x04 but it can be 0xaa */
	if(tvb_get_guint8(tvb, offset + 12) > 0x04){
		if(tvb_get_guint8(tvb, offset + 12) != 0xaa)
			return FALSE;		
	}
	
	/*id_msg should be under 0x07 */
	if(tvb_get_guint8(tvb, offset + 13) > 0x07){
		return FALSE;
	}
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NoTA L_IN");
	col_clear(pinfo->cinfo, COL_INFO);
			
	ia_dst = tvb_get_letohl(tvb, offset + 0);
	ia_src = tvb_get_letohl(tvb, offset + 4);
	nota_ttl = tvb_get_guint8(tvb, offset + 8);
	nota_id_pdu = tvb_get_letohs(tvb, offset + 10);
	nota_id_prot = tvb_get_guint8(tvb, offset + 12);
	nota_id_msg = tvb_get_guint8(tvb, offset + 13);
	nota_len_pl = tvb_get_letohs(tvb, offset + 14);
	
	
	col_append_fstr(pinfo->cinfo, COL_INFO, "IA: %x > %x, TTL: %u",
    	ia_src, ia_dst, nota_ttl);


	if (tree) {
		proto_item *nota_item;

		nota_item = proto_tree_add_protocol_format(tree, proto_nota, tvb, 0, -1,
			"Network on Terminal Architecture, Src IA: %x, Dst IA: %x",
			ia_src, ia_dst);
		nota_tree = proto_item_add_subtree(nota_item, ett_nota);
	}


	if (nota_tree) {

		proto_tree_add_uint(nota_tree, hf_nota_ttl,
			tvb, offset + 8, 1, nota_ttl);
		
		proto_tree_add_uint(nota_tree, hf_nota_id_pdu,
		tvb, offset + 10, 2, nota_id_pdu);

	}

rest_length = tvb_reported_length(tvb) - 13;
next_tvb = tvb_new_subset(tvb, 13, rest_length , rest_length);
	
	/* Switch-case for different protocol and message IDs and calls for individual
	functions */
	if(nota_tree){

		proto_item *LINup_item;
		proto_tree 	*LINup_tree;
	
		LINup_item = proto_tree_add_text(nota_tree, tvb, offset + 12, 1, "Protocol: %s(%x) (%u bytes of payload)", 
			val_to_str(nota_id_prot, names_lin_prot_types, "%u"), nota_id_prot, nota_len_pl);

		LINup_tree = proto_item_add_subtree(LINup_item, ett_nota_LINup);
		
		switch (nota_id_prot) {
			case IARP:
				col_append_fstr(pinfo->cinfo, COL_INFO, " IARP-> %s",
			    	val_to_str(nota_id_msg, names_iarp_messages, "Unknown type"));
				offset += dissect_nota_IARP(next_tvb, LINup_tree);
			break;
			case PAP:
				col_append_fstr(pinfo->cinfo, COL_INFO, " PAP-> %s",
		    		val_to_str(nota_id_msg, names_pap_messages, "Unknown type"));
				offset += dissect_nota_PAP(next_tvb, LINup_tree);
			break;
			case CMP:
				col_append_fstr(pinfo->cinfo, COL_INFO, " CMP-> %s",
			    	val_to_str(nota_id_msg, names_cmp_messages, "Unknown type"));
				offset += dissect_nota_CMP(next_tvb, LINup_tree);
			break;
			case GEN:
				col_append_fstr(pinfo->cinfo, COL_INFO, " GEN-> %s",
			    	val_to_str(nota_id_msg, names_gen_messages, "Unknown type"));
				offset += dissect_nota_GEN(next_tvb, LINup_tree);
			break;
			case USR:
				col_append_fstr(pinfo->cinfo, COL_INFO, " USR-> %s",
			    	val_to_str(nota_id_msg, names_usr_messages, "Unknown type"));
				offset += dissect_nota_USR(next_tvb, pinfo, LINup_tree, tree);
			break;
		
			default:
				call_dissector(data_handle,next_tvb, pinfo, nota_tree);
			break;
		}
	}
	

/*	rest_length = tvb_reported_length(tvb) - offset;
	
	proto_tree_add_text(nota_tree, tvb, 0, 2, "Supposed lenght: %u",
		rest_length);
	
	next_tvb = tvb_new_subset(tvb, 16, rest_length , rest_length);
	call_dissector(data_handle,next_tvb, pinfo, nota_tree);*/
		return TRUE;
}


void proto_reg_handoff_nota(void);

void
proto_register_nota(void)
{
  static hf_register_info hf[] = {

	/*----ADDED */
	{ &hf_nota_ia_dst,
		{"IA Destination", "nota.ia_dst", FT_INT32, BASE_DEC,
		NULL, 0x0, "IA Destination", HFILL}},		
	{ &hf_nota_ia_src,
		{"IA Source", "nota.ia_src",
		FT_INT32, BASE_DEC, NULL, 0x0,
		"IA Source", HFILL}},		
	{ &hf_nota_ttl,
		{ "TTL", "nota.ttl", FT_UINT8, BASE_DEC,
		NULL, 0x0, "Time-to-live", HFILL }},
	{ &hf_nota_id_pdu,
		{ "PDU ID", "nota.id_pdu", FT_UINT16, BASE_DEC,
		NULL, 0x0, "NoTA PDU ID", HFILL }},
	{ &hf_nota_id_prot,
		{ "Protocol ID", "nota.id_prot", FT_UINT8, BASE_HEX,
		NULL, 0x0, "NoTA H_IN Protocol ID", HFILL }},
	{ &hf_nota_id_msg,
		{ "Message ID", "nota.id_msg", FT_UINT8, BASE_HEX,
		NULL, 0x0, "NoTA H_IN Message ID", HFILL }},		
	{ &hf_nota_len_pl,
		{"Payload length", "nota.len_pl", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Payload length", HFILL}},
	
	{ &hf_t_ia_own,
		{"User IA ", "nota.iarp.ia_own", FT_INT32, BASE_DEC,
		NULL, 0x0, "IARP: User IA address", HFILL}},
	{ &hf_t_ia_other,
		{"Other IA ", "nota.iarp.ia_other", FT_INT32, BASE_DEC,
		NULL, 0x0, "IARP: Other IA address", HFILL}},
		
	{ &hf_pai_length,
		{"PAI payload length", "nota.len_pai", FT_UINT16, BASE_DEC,
		NULL, 0x0, "PAI payload length", HFILL}},
		
	{ &hf_t_lsockid,
		{"L_INup socket ID", "nota.lsockid", FT_UINT32, BASE_HEX,
		VALS(names_t_lsockid), 0x0, "Remote peer L_INup node type", HFILL}},
	{ &hf_t_ldsockid,
		{"L_INdown socket ID", "nota.ldsockid", FT_UINT32, BASE_HEX,
		VALS(names_t_ldsockid), 0x0, "Remote L_INdown socket ID", HFILL}},
	{ &hf_t_loffset,
		{"l_offset: for future use", "nota.offset", FT_UINT64, BASE_HEX,
		NULL, 0x0, "l_offset: for future use", HFILL}},

	{ &hf_t_cookie,
		{"Cookie ", "nota.cookie", FT_STRING, BASE_NONE,
		NULL, 0x0, "Cookie: for future use", HFILL}},
	{ &hf_t_lup_type,
		{"L_INup node capability information", "nota.luptype", FT_UINT32, BASE_HEX,
		VALS(names_t_luptype), 0x0, "L_INup node capability information", HFILL}},
		
	{ &hf_t_ldtype_main,
		{"L_INdown main transport type category", "nota.ldtype.main", FT_INT32, BASE_DEC,
		VALS(names_t_ldtype_main), 0x0, "L_INdown main transport type category", HFILL}},
	{ &hf_t_ldtype_ext,
		{"L_INdown transport type extension mask", "nota.ldtype.ext", FT_UINT32, BASE_HEX,
		NULL, 0x0, "L_INdown transport type extension mask", HFILL}},
	{ &hf_t_ldtype_ext_ip,
		{"L_INdown transport type extension mask", "nota.ldtype.ext", FT_UINT32, BASE_HEX,
		VALS(names_t_ldtype_ext_ip), 0x0, "L_INdown transport type extension mask", HFILL}},
		
	{ &hf_t_ldnetid,
		{"L_INdown network ID", "nota.ldnetid", FT_UINT32, BASE_HEX,
		NULL, 0x0, "L_INdown network ID", HFILL}},
	
	{ &hf_t_levent,
		{"L_INup peer event:", "nota.levent", FT_UINT32, BASE_HEX,
		VALS(names_t_levent), 0x0, "L_INup peer event", HFILL}},
	{ &hf_t_lerror,
		{"L_INup peer error message: ", "nota.lerror", FT_UINT32, BASE_HEX,
		VALS(names_t_lerror), 0x0, "L_INup peer error message", HFILL}},
		
	{ &hf_nota_IARP_message,
		{"IARP message", "nota.iarp.message", FT_UINT8, BASE_HEX,
		VALS(names_iarp_messages), 0x0, "IARP message", HFILL}},
	{ &hf_nota_PAP_message,
		{"PAP message", "nota.pap.message", FT_UINT8, BASE_HEX,
		VALS(names_pap_messages), 0x0, "PAP message", HFILL}},
	{ &hf_nota_CMP_message,
		{"CMP message", "nota.cmp.message", FT_UINT8, BASE_HEX,
		VALS(names_cmp_messages), 0x0, "CMP message", HFILL}},
	{ &hf_nota_GEN_message,
		{"GEN message", "nota.cmp.message", FT_UINT8, BASE_HEX,
		VALS(names_gen_messages), 0x0, "GEN message", HFILL}},
	{ &hf_nota_USR_message,
		{"USR message", "nota.usr.message", FT_UINT8, BASE_HEX,
		VALS(names_usr_messages), 0x0, "USR message", HFILL}},
		

  };
	static gint *ett[] = {
		&ett_nota,
		&ett_nota_LINup,
		&ett_nota_cmap_cnf,
	};

	proto_nota = proto_register_protocol("Nota",
					"NoTA", "nota");
	proto_register_field_array(proto_nota, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_register_nota_high(void)
{
  static hf_register_info hf[] = {

	/*----ADDED */
	{ &hf_hsrc_ia,
		{"Source subsystem IA", "nota.high.srcIA", FT_INT32, BASE_DEC,
		NULL, 0x0, "IA Destination", HFILL}},
	{ &hf_hlen_pl,
		{"Payload length", "nota.high.len_pl", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Payload length", HFILL}},
	{ &hf_hpdu_id,
		{"PDU ID", "nota.high.pdu_id", FT_UINT16, BASE_DEC,
		NULL, 0x0, "High Interconnect PDU ID", HFILL}},
	{ &hf_hprot_id,
		{"Protocol ID", "nota.high.prot_id", FT_UINT16, BASE_HEX,
		NULL, 0x0, "High interconnect protocol ID", HFILL}},
	{ &hf_hmsg_id,
		{"Message ID", "nota.high.msg_id", FT_UINT16, BASE_HEX,
		NULL, 0x0, "High interconnect message ID", HFILL}},
	
	{ &hf_nota_high_SHP_message,
		{"SHP message", "nota.high.shp.message", FT_UINT16, BASE_HEX,
		VALS(names_shp_messages), 0x0, "SHP message", HFILL}},
	{ &hf_nota_high_SRP_message,
		{"SRP message", "nota.high.shp.message", FT_UINT16, BASE_HEX,
		VALS(names_srp_messages), 0x0, "SRP message", HFILL}},
	{ &hf_nota_high_SDP_message,
		{"SDP message", "nota.high.shp.message", FT_UINT16, BASE_HEX,
		VALS(names_sdp_messages), 0x0, "SDP message", HFILL}},
	{ &hf_nota_high_SAP_message,
		{"SAP message", "nota.high.sap.message", FT_UINT16, BASE_HEX,
		VALS(names_sap_messages), 0x0, "SAP message", HFILL}},
		
	{ &hf_t_hrel_primary,
		{"Release number primary", "nota.high.release.prim", FT_UINT8, BASE_DEC,
		NULL, 0x0, "Primary release number", HFILL}},
	{ &hf_t_hrel_secondary,
		{"Release number secondary", "nota.high.release.sec", FT_UINT8, BASE_DEC,
		NULL, 0x0, "Secondary release number", HFILL}},
	{ &hf_t_hflags,
		{"H_IN PDU flags", "nota.high.flags", FT_UINT16, BASE_HEX,
		NULL, 0x0, "High interconnect PDU flags", HFILL}},
	{ &hf_t_hmsg_len,
		{"Message length", "nota.high.msg_len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "High interconnect message length", HFILL}},
	{ &hf_t_hstatus,
		{"Status: ", "nota.high.status", FT_UINT16, BASE_HEX,
		VALS(names_t_hstatus), 0x0, "High interconnect status reply ", HFILL}},
	{ &hf_t_sid,
		{"SID: ", "nota.high.sid", FT_UINT32, BASE_DEC,
		VALS(names_t_sid), 0x0, "High interconnect service identifier ", HFILL}},
	{ &hf_t_ia,
		{"IA: ", "nota.high.ia", FT_INT32, BASE_DEC,
		NULL, 0x0, "Interconnect address", HFILL}},
	{ &hf_t_hsockid,
		{"Socket ID: ", "nota.high.sock_id", FT_UINT32, BASE_DEC,
		NULL, 0x0, "High interconnect socket ID ", HFILL}},
	{ &hf_t_hportid,
		{"Port ID: ", "nota.high.sock_id", FT_UINT32, BASE_DEC,
		NULL, 0x0, "High interconnect port ID ", HFILL}},
			
	{ &hf_high_sid_entries,
		{"SID entries: ", "nota.high.sid_number", FT_UINT16, BASE_DEC,
		NULL, 0x0, "High interconnect number of received SID-IA pairs ", HFILL}},



  };
	static gint *ett[] = {
		&ett_nota_high,
		&ett_nota_high_msg,
		&ett_nota_high_sdp_cnf
	};

	proto_nota_high = proto_register_protocol("Nota High Interconnect",
					"NoTA H_IN", "nota.high");
	proto_register_field_array(proto_nota_high, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nota_high(void)
{
}

void
proto_reg_handoff_nota(void)
{
	static gboolean Initialized=FALSE;

	if (!Initialized) {
		heur_dissector_add("tcp", dissect_nota, proto_nota);
		
		nota_high_handle = create_dissector_handle(dissect_nota_high, proto_nota_high);
		data_handle = find_dissector("data");
		Initialized=TRUE;
	} else {
	/*	dissector_delete("tcp.port", ServerPort, nota_handle);*/
	}

}


