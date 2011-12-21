/* packet-nota_down.c
 * Routines for NoTA L_INdown packet dissection
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
#include <epan/prefs.h>
//#include "packet-nota.h"

static int proto_nota_down = -1;

/*L_INdown transport level */
static int hf_nota_ldmsg_type = -1;
static int hf_nota_ld_tranid = -1;
static int hf_nota_ld_src_sockid = -1;
static int hf_nota_ld_dst_sockid = -1;
static int hf_nota_ld_cl_endpoint = -1;
static int hf_nota_ld_co_endpoint = -1;
static int hf_nota_ld_status = -1;
/*static int hf_nota_ld_nodetype = -1; already as luptype*/
static int hf_nota_ld_addr_family = -1;
static int hf_nota_ld_addr = -1;
q
/* Now added*/
static int hf_nota_ldsockid_local = -1;
static int hf_nota_ldsockid_remote = -1;
static int hf_nota_ldsocktype = -1;
static int hf_nota_ldtype_main = -1;
static int hf_nota_ldtype_ext = -1;
static int hf_nota_luptype = -1;
//static int hf_nota_ldstatus = -1;
static int hf_nota_down_length = -1;
static int hf_nota_down_pai_length = -1;

static int hf_nota_lin_down = -1;

static gint ett_nota_transport = -1;
static gint ett_nota_down = -1;
static gint ett_nota = -1;

//static dissector_handle_t nota_down_handle;
/*static dissector_handle_t nota_transport_handle;*/
static dissector_handle_t nota_handle;
static dissector_handle_t data_handle;

/* these names are directly out of the NoTA source. */
#define LD_TCP_CONN_REQ_MSG_TYPE    0x00               /* Connection request message type */
#define LD_TCP_CONN_RSP_MSG_TYPE    0x01               /* Connection response message type */
#define LD_TCP_SCENE_REQ_MSG_TYPE   0x10               /* Scene request message type */
#define LD_TCP_SCENE_RSP_MSG_TYPE   0x11               /* Scene response message type */
#define LD_TCP_CL_ACK_MSG_TYPE      0x12               /* Connection-less acknowledgement message type */

static const value_string names_ld_msg_type[] = {
        { LD_TCP_CONN_REQ_MSG_TYPE, "Connection request" },
        { LD_TCP_CONN_RSP_MSG_TYPE, "Connection response" },
        { LD_TCP_SCENE_REQ_MSG_TYPE, "Scene request" },
		{ LD_TCP_SCENE_RSP_MSG_TYPE, "Scene response" },
		{ LD_TCP_CL_ACK_MSG_TYPE, "Connection-less acknowledgement" },
		{ 0, NULL}
};

//#define DEFAULTnotaPort 2345

//static guint notaUDPPort=DEFAULTnotaPort;
//static guint defaultMulticastPort = DEFAULTnotaPort;

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
/* t_lsockid */
#define L_SOCKID_ANY	-1
#define L_SOCKID_ERROR	-2
/* t_lsocktype */
#define L_SOCKTYPE_NA	0 /* Unknown socket type */
#define L_SOCKTYPE_CL	1 /* Connectionless socket */
#define L_SOCKTYPE_CO	2 /* Connection-oriented socket */
/* t_lerror */
#define ERR_GENERAL		1
#define ERR_UNKNOWN_PDU 2
#define ERR_UNKNOWN_IA	3
#define ERR_UNKNOWN_LSOCKID	4
#define ERR_TIMEOUT		5
#define ERR_PDU_SIZE_EXCEEDED	6
/* t_ldsockid */
#define LD_SOCKID_ANY	-1 /* Used for opening any free L_INdown socket */
#define LD_SOCKID_ERROR	-2 /* Socket operation failed */
#define LD_SOCKID_NA	-3 /* Socket not available */

static const value_string names_t_ldsockid[] = {
		{LD_SOCKID_ANY, "Any free Ld socket"},
		{LD_SOCKID_ANY, "Socket operation failed"},
		{LD_SOCKID_ANY, "Socket not available"},
		{0, NULL},
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
		{0, NULL},
};

/* t_ldstatus */
#define LD_STATUS_OK	-1	/*Success*/
#define LD_STATUS_NOK	-2	/* Failure */
#define LD_STATUS_DISCONNECTED	-3
#define LD_STATUS_NOT_AVAILABLE -4
#define LD_STATUS_TOO_LONG		-5
#define L_STATUS_PEER_ACTIVATED -6 /* Disconnected with reason */
#define L_STATUS_UNKNOWN		-7 /* Disconnected with reason */

static const value_string names_t_ld_status[] = {
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
/* t_levent */
#define L_EVENT_MNG_IA_CHANGED	1	/* Indication about L_INup manager node IA change. */
#define L_EVENT_SUBSYST_RESET	2	/* Request to perform sub-system hard reset. */


static gboolean dissect_nota_down(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_reg_handoff_nota_down(void);


static void	dissect_conn_req(tvbuff_t *tvb, proto_tree *tree)
{
	//guint8 tranid;
	if (tree) {
		
		//tranid = tvb_get_guint8(tvb, 0);
	/*	proto_tree_add_uint(tree, hf_nota_ld_tranid,
			tvb, 0, 1, tranid);
	*/		proto_tree_add_item(tree, hf_nota_ld_tranid, tvb, 0, 1, TRUE);
	/*		
		src_sockid = tvb_get_ntohl(tvb, 1);
		proto_tree_add_uint(tree, hf_nota_ld_src_sockid,
			tvb, 1, 4, src_sockid);
			
		dst_sockid = tvb_get_ntohl(tvb, 5);
		proto_tree_add_uint(tree, hf_nota_ld_dst_sockid,
			tvb, 5, 4, dst_sockid);
	*/
	proto_tree_add_item(tree, hf_nota_ldsockid_local, tvb, 1, 4, TRUE);
	proto_tree_add_item(tree, hf_nota_ldsockid_remote, tvb, 5, 4, TRUE);
		
		proto_tree_add_item(tree, hf_nota_ld_cl_endpoint, tvb, 9, 2, TRUE);
		proto_tree_add_item(tree, hf_nota_ld_co_endpoint, tvb, 11, 2, TRUE);

		}
}

static void	dissect_conn_rsp(tvbuff_t *tvb, proto_tree *tree)
{
//	guint8 		tranid;
/*	guint8		status;*/
	if (tree) {
		
		//tranid = tvb_get_guint8(tvb, 0);
		proto_tree_add_item(tree, hf_nota_ld_tranid,
			tvb, 0, 1, TRUE);
			
/*		status = tvb_get_guint8(tvb, 1);*/
		proto_tree_add_item(tree, hf_nota_ld_status,
			tvb, 1, 1, TRUE);
			
		}
}

static void	dissect_scene_req(tvbuff_t *tvb, proto_tree *tree)
{
/*	guint8 tranid;
	guint32		node_type;*/
	if (tree) {
		
	//	tranid = tvb_get_guint8(tvb, 0);
		proto_tree_add_item(tree, hf_nota_ld_tranid,
			tvb, 0, 1, TRUE);

	//	node_type = tvb_get_ntohl(tvb, 1);
		proto_tree_add_item(tree, hf_nota_luptype,
			tvb, 1, 4, FALSE);

		}
}


static void	dissect_scene_rsp(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 tranid;
	guint32		node_type;
	guint16		addr_family;
	guint32		addr;
	
	if (tree) {
	
		addr_family = tvb_get_ntohs(tvb, 5);
		addr = tvb_get_ipv4(tvb, 7);
		
		tranid = tvb_get_guint8(tvb, 0);
		proto_tree_add_uint(tree, hf_nota_ld_tranid,
			tvb, 0, 1, tranid);

		node_type = tvb_get_ntohl(tvb, 1);
		proto_tree_add_uint(tree, hf_nota_luptype,
			tvb, 1, 4, node_type);
			
		proto_tree_add_item(tree, hf_nota_ld_addr_family, tvb, 5, 2, FALSE);
		proto_tree_add_ipv4(tree, hf_nota_ld_addr, tvb, 7, 4, addr );
		
		/*According to ld adapter documentation these go UDP -> TCP port but
		the traffic for TCP uses the port defined by UDP...*/
		proto_tree_add_item(tree, hf_nota_ld_cl_endpoint, tvb, 11, 2, FALSE);
		proto_tree_add_item(tree, hf_nota_ld_co_endpoint, tvb, 13, 2, FALSE);

			
		}
}


static gboolean
dissect_nota_down(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*nota_down_tree = NULL;
	
	/* LdTCP <-> LdTCP messages */
	guint8		msg_type;
	guint32		length;
	tvbuff_t	*next_tvb;

	
	int offset = 0;

	
	/* Check to see if there is enough data
	  to make a NoTAdown-packet */
	if(tvb_reported_length(tvb) < 1){
		return FALSE;
	}
	if(tvb_get_guint8(tvb, 0) != 0x00 && tvb_get_guint8(tvb, 0) != 0x01 &&
	tvb_get_guint8(tvb, 0) != 0x10 && tvb_get_guint8(tvb, 0) != 0x11 && 
	tvb_get_guint8(tvb, 0) != 0x12)
	{
		return FALSE;
	}
	
	
	
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NoTA-L_IN(down)");
	
	col_clear(pinfo->cinfo, COL_INFO);
	/*packet message:
	* 32 bit ldsockid(local) | t_pai(length 16 bit + length*byte)
	* 32 bit ldsockid(remote) | payload(length 32 bit + length*byte)
	*/

	if (tree) {
		proto_item *nota_down_item;
		
		/*nota_down_item = proto_tree_add_text(tree, tvb, 0, -1,
			"Network on Terminal Architecture(L_INdown)");*//*Print message type here? */
		nota_down_item = proto_tree_add_protocol_format(tree, proto_nota_down, tvb, 0, -1,
		"NoTA L_INdown");
		nota_down_tree = proto_item_add_subtree(nota_down_item, ett_nota_down);
		

	}

		
		msg_type = tvb_get_guint8(tvb, offset);
		
		/*Add the msg-type to Protocol column header */
		col_append_fstr(pinfo->cinfo, COL_INFO, "Ldown: %s", val_to_str(msg_type, names_ld_msg_type, "Unknown msg type"));
		
		
		length = tvb_reported_length(tvb) - 1;
		next_tvb = tvb_new_subset(tvb, 1, length, length);
	

	if (nota_down_tree) {
		proto_item	*notaLd_item;
		proto_tree 	*notaLd_tree;
		
		notaLd_item = proto_tree_add_uint(nota_down_tree, hf_nota_ldmsg_type,
					tvb, 0, 1, msg_type);
		notaLd_tree = proto_item_add_subtree(notaLd_item, ett_nota_transport);


				switch (msg_type) {
					case LD_TCP_CONN_REQ_MSG_TYPE:
						dissect_conn_req(next_tvb, notaLd_tree);
					break;
					case LD_TCP_CONN_RSP_MSG_TYPE:
						dissect_conn_rsp(next_tvb, notaLd_tree);
					break;
					
					case LD_TCP_SCENE_REQ_MSG_TYPE:
						dissect_scene_req(next_tvb, notaLd_tree);
					break;
					case LD_TCP_SCENE_RSP_MSG_TYPE:
						dissect_scene_rsp(next_tvb, notaLd_tree);
					break;
					
					case LD_TCP_CL_ACK_MSG_TYPE:
						/* Do nothing */
					break;
					
					default:
						call_dissector(data_handle, next_tvb, pinfo, nota_down_tree);
					break;
				}

				/*call for nota?, now just data */
		/*		call_dissector(data_handle,next_tvb, pinfo, nota_tree);*/
		
	
	}
	/*length = tvb_get_ntohl(tvb, offset);*/
/*	length = tvb_reported_length(tvb) - offset;
*	next_tvb = tvb_new_subset(tvb, offset, length, length);
*	
*	call_dissector(data_handle,next_tvb, pinfo, nota_down_tree);
*/
return TRUE;
}




void
proto_register_nota_down(void)
{
  static hf_register_info hf[] = {
	/*Tree fields */
	{ &hf_nota_lin_down,
      { "Nota Ld field", "nota.LINdown", FT_STRINGZ, BASE_NONE,
		NULL, 0x0, "NoTA Ld-field", HFILL }},
	
	/*L_INdown transport layer */		
    { &hf_nota_ldmsg_type,
		{"Ld Message type", "nota.down.message.type", FT_UINT8, BASE_HEX,
		VALS(names_ld_msg_type), 0x0, "L_INdown transport (TCP) layer message type", HFILL}},
	{ &hf_nota_ld_tranid,
		{"Ld Tran ID", "nota.down.tranid", FT_UINT8, BASE_HEX,
		NULL, 0x0, "L_INdown transport (TCP) layer transmission ID", HFILL}},
	{ &hf_nota_ld_src_sockid,
		{"Ld Source SockID", "nota.down.sock.src", FT_INT32, BASE_DEC,
		VALS(names_t_ldsockid), 0x0, "L_INdown transport (TCP) layer Client Socket ID", HFILL}},
	{ &hf_nota_ld_dst_sockid,
		{"Ld Destination SockID", "nota.down.sock.dest", FT_INT32, BASE_DEC,
		VALS(names_t_ldsockid), 0x0, "L_INdown transport (TCP) layer Server Socket ID", HFILL}},
	{ &hf_nota_ld_cl_endpoint,
		{"Ld UDP port", "nota.down.listen.udp", FT_UINT16, BASE_DEC,
		NULL, 0x0, "L_INdown transport: UDP port to listen", HFILL}},
	{ &hf_nota_ld_co_endpoint,
		{"Ld TCP port", "nota.down.listen.tcp", FT_UINT16, BASE_DEC,
		NULL, 0x0, "L_INdown transport: TCP port to listen", HFILL}},
	{ &hf_nota_ld_status,
		{"Ld node status", "nota.down.status", FT_INT8, BASE_DEC,
		NULL, 0x0, "L_INup node status", HFILL}},
		
	{ &hf_nota_ld_addr_family,
		{"Ld: AF_INET", "nota.down.addr.family", FT_UINT16, BASE_HEX,
		NULL, 0x0, "L_INdown transport (TCP) layer IP family", HFILL}},
	{ &hf_nota_ld_addr,
		{"Ld: IP address", "nota.down.addr", FT_IPv4, BASE_NONE,
		NULL, 0x0, "L_INdown transport (TCP) layer IP family", HFILL}},

	/* L_IN up layer */
	{ &hf_nota_ldsockid_local,
		{"Socket ID local", "nota.down.socket.local", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Local Socket ID", HFILL}},
	{ &hf_nota_ldsockid_remote,
		{"Socket ID remote", "nota.down.socket.remote", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Remote Socket ID", HFILL}},
	{ &hf_nota_ldsocktype,
		{"Socket type", "nota.down.sock.type", FT_UINT32, BASE_HEX,
		NULL, 0x0, "L_INdown socket ID", HFILL}},
	/*---ldtype_main, ext, ldstatus should be INT32 but changed UINT to work with BASE_HEX */
	{ &hf_nota_ldtype_main,
		{"L_INdown main transport type category", "nota.down.type.main", FT_UINT32, BASE_HEX,
		NULL, 0x0, "L_INdown main transport type category", HFILL}},
	{ &hf_nota_ldtype_ext,
		{"L_INdown transport type extension mask", "nota.down.type.ext", FT_UINT32, BASE_HEX,
		NULL, 0x0, "L_INdown transport type extension mask", HFILL}},
	{ &hf_nota_luptype,
		{"Up node capability", "nota.down.luptype", FT_UINT32, BASE_DEC,
		VALS(names_t_luptype), 0x0, "L_INup node capability information", HFILL}},
	{ &hf_nota_down_length,
		{"Payload length", "nota.down.pl_length", FT_UINT32, BASE_DEC,
		NULL, 0x0, "L_IN(down) Payload length", HFILL}},
	{ &hf_nota_down_pai_length,
		{"PAI length", "nota.down.pai_length", FT_UINT16, BASE_DEC,
		NULL, 0x0, "PAI data segment length in bytes", HFILL}},

    
  };
	static gint *ett[] = {
		&ett_nota_down,
		&ett_nota_transport,
		&ett_nota,
	};
//	module_t *nota_down_module;

	proto_nota_down = proto_register_protocol("Nota-LINdown)",
					"NoTAdown", "nota.down");
	proto_register_field_array(proto_nota_down, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
/*	nota_down_module = prefs_register_protocol(proto_nota_down,
		proto_reg_handoff_nota_down);
	prefs_register_uint_preference(nota_down_module, "udp.port",
					"NoTA UDP port",
					"Set the UDP port for NoTA L_IN down protocol",
					10, &notaUDPPort);
*/				
/*	prefs_register_uint_preference(nota_down_module, "tcp.port",
					"NoTA TCP port",
					"Set the TCP port for NoTA L_IN down protocol",
					10, &notaTCPPort);
*/
}


void
proto_reg_handoff_nota_down(void)
{
	static gboolean Initialized=FALSE;
//	static guint ServerPort;
/*	static guint ServerPort2; */

	if (!Initialized) {
		//nota_down_handle = create_dissector_handle(dissect_nota_down, proto_nota_down);
		/*Connect req&rsp sent in TCP after finding node->heuristic dissect for it*/
		heur_dissector_add("tcp", dissect_nota_down, proto_nota_down);
		heur_dissector_add("udp", dissect_nota_down, proto_nota_down);
		
		nota_handle = find_dissector("nota");
		data_handle = find_dissector("data");
		Initialized=TRUE;
	} else {
	//dissector_delete("udp.port", ServerPort, nota_down_handle);
/*		dissector_delete("tcp.port", ServerPort2, nota_down_handle); */
	}

	/* set port for future deletes */
//	ServerPort=notaUDPPort;
/*	ServerPort2=notaTCPPort; */

//	dissector_add("udp.port", notaUDPPort, nota_down_handle);
//	dissector_add("udp.port", defaultMulticastPort, nota_down_handle);
	
	/*TEST*/
/*	dissector_add("tcp.port", notaTCPPort, nota_down_handle); */
}


