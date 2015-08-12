/* packet-chat.c
 * Author:  Toan Pham, Atronix Engineering Inc.
 * Description: Chat dissector to decode Swiftdecoder chat messages
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

/* Chat Type */
static int proto_chat = -1;



/* Chat Header */
static int hf_chat_scn = -1;
static int hf_chat_sct = -1;
static int hf_chat_rcn = -1;
static int hf_chat_rct = -1;
static int hf_chat_mt  = -1;
static int hf_chat_payload  = -1;




#define MT_HEALTH 	0
#define MT_HB 		1
#define MT_PLCINFO	2
#define MT_SCAN_DATA2 	3






static gint ett_chat = -1;

#define TCP_PORT_chat		    42300
#define TCP_PORT_DchatPROXY		57000
/* good candidate for dynamic port specification */


enum chat_fields{
	cfield_scn = 0,
	cfield_sct,
	cfield_rcn,
	cfield_rct,
	cfield_mt,
	cfield_payload,
};

#define TAG(index,name,shortname,description) \
      { &index, { name,shortname, FT_STRING, BASE_NONE, NULL, 0x0, description, HFILL }},


struct chat_field_info {
    int index_position;		/* position after MT */
    int id; 			/* for wireshark dissector */
    const char *name;
    const char *shortname;
    const char *description;
};


struct chat_message_type {
    const char * name;        /* Message Type Match String */
    int id;		/* Register ID */
    const char * shortname;   /* Wireshark Search name */
    const char * description;
    struct chat_field_info *chat_info;
};

struct chat_field_info cf_scan_data2[] = {
  {.index_position = 0, .name = (char *)"firstfield", .shortname = (char *)"longername", .description = (char *)"asdfasdfasdf" },
  {.index_position = 1, .name = (char *)"firstfield1", .shortname = (char *)"longername1", .description = (char *)"asdfasdfasdf1" },
  {.index_position = -1}
};

struct chat_field_info cf_plcinfo[] = {
  {.index_position = 0, .name = (char *)"ID", .shortname = (char *)"chat.mt.plcinfo.msgid", .description = (char *)"asdfasdfasdf" },
  {.index_position = 1, .name = (char *)"Speed", .shortname = (char *)"chat.mt.plcinfo.speed", .description = (char *)"asdfasdfasdf1" },
  {.index_position = 2, .name = (char *)"Machine Stat", .shortname = (char *)"chat.mt.plcinfo.machstat", .description = (char *)"asdfasdfasdf1" },
  {.index_position = 3, .name = (char *)"System Revs", .shortname = (char *)"chat.mt.plcinfo.sysrevs", .description = (char *)"asdfasdfasdf1" },
  {.index_position = 4, .name = (char *)"Active Camera", .shortname = (char *)"chat.mt.plcinfo.activecamera", .description = (char *)"asdfasdfasdf1" },
  {.index_position = -1}
};


struct chat_field_info cf_health[] = {
  {.index_position = 0, .name = (char *)"ID", .shortname = (char *)"chat.mt.health.id", .description = (char *)"Message ID" },
  {.index_position = 1, .name = (char *)"Status", .shortname = (char *)"chat.mt.health.status", .description = (char *)"Status" },
  {.index_position = -1}
};

struct chat_field_info cf_heartbeat[] = {
  {.index_position = 0, .name = (char *)"ID", .shortname = (char *)"chat.mt.heartbeat.id", .description = (char *)"Message ID" },
  {.index_position = 1, .name = (char *)"Status", .shortname = (char *)"chat.mt.heartbeat.status", .description = (char *)"Status" },
  {.index_position = -1}
};

struct chat_field_info cf_hb[] = {
  {.index_position = 0, .name = (char *)"ID", .shortname = (char *)"chat.mt.hb.id", .description =(char *) "Message ID" },
  {.index_position = -1}
};

struct chat_field_info cf_sort[] = {
  {.index_position = 0, .name = "ID", .shortname = "chat.mt.sort.id", .description = "ID" },
  {.index_position = 1, .name = "PKGUID", .shortname = "chat.mt.sort.pkguid", .description = "Package UID" },
  {.index_position = 2, .name = "TRKNUM", .shortname = "chat.mt.sort.trknum", .description = "Tracking Number" },
  {.index_position = 3, .name = "DIMS", .shortname = "chat.mt.sort.dims", .description = "Dimensional Data" },
  {.index_position = 4, .name = "DEST1", .shortname = "chat.mt.sort.dest1", .description = "" },
  {.index_position = 5, .name = "DEST2", .shortname = "chat.mt.sort.dest2", .description = "" },
  {.index_position = 6, .name = "DEST3", .shortname = "chat.mt.sort.dest3", .description = "" },
  {.index_position = 7, .name = "DEST4", .shortname = "chat.mt.sort.dest4", .description = "" },
  {.index_position = 8, .name = "DEST5", .shortname = "chat.mt.sort.dest5", .description = "" },
  {.index_position = 9, .name = "DEST6", .shortname = "chat.mt.sort.dest6", .description = "" },
  {.index_position = 10, .name = "DEST7", .shortname = "chat.mt.sort.dest7", .description = "" },
  {.index_position = 11, .name = "DEST8", .shortname = "chat.mt.sort.dest8", .description = "" },
  {.index_position = 12, .name = "DEST9", .shortname = "chat.mt.sort.dest9", .description = "" },
  {.index_position = -1}
};

struct chat_field_info cf_id[] = {
  {.index_position = 0, .name = "MSGID", .shortname = "chat.mt.id.msgid", .description = "Message ID" },
  {.index_position = 1, .name = "PLCID", .shortname = "chat.mt.id.plcid", .description = "Message ID" },
  {.index_position = -1}
};

struct chat_field_info cf_sortconf[] = {
  {.index_position = 0, .name = "MSGID", .shortname = "chat.mt.sortconf.msgid", .description = "" },
  {.index_position = 1, .name = "PKGUID", .shortname = "chat.mt.sortconf.pkguid",.description = "" },
  {.index_position = 2, .name = "TRKNUM", .shortname = "chat.mt.sortconf.trknum",.description = "" },
  {.index_position = 3, .name = "DEST", .shortname = "chat.mt.sortconf.dest",.description = "" },
  {.index_position = 4, .name = "PACKSTAT", .shortname = "chat.mt.sortconf.packstat",.description = "" },
  {.index_position = 5, .name = "PACKREVS", .shortname = "chat.mt.sortconf.packrevs",.description = "" },
  {.index_position = -1}
};

struct chat_field_info cf_contclose[] = {
  {.index_position = 0, .name = "MSGID", .shortname = "chat.mt.contclose.msgid", .description = "" },
  {.index_position = 1, .name = "DEST", .shortname = "chat.mt.contclose.dest",.description = "" },
  {.index_position = -1}
};

struct chat_field_info cf_plcmsg[] = {
  {.index_position = 0, .name = "PLCID", .shortname = "chat.mt.plc_msg.plcid", .description = "" },
  {.index_position = -1}
};


struct chat_message_type chat_mesage_table[] = {
  { .name = "HEARTBEAT",.shortname = "chat.mt.heartbeat", 	.chat_info = cf_heartbeat},
  { .name = "HEALTH", 	.shortname = "chat.mt.health", 		.chat_info = cf_health},
  { .name = "HB", 	.shortname = "chat.mt.hb", 		.chat_info = cf_hb},
  { .name = "SCAN_DATA2", .shortname = "chat.mt.scan_data2", 	.chat_info = cf_scan_data2},
  { .name = "PLCINFO", .shortname = "chat.mt.plcinfo",		.chat_info = cf_plcinfo},
  { .name = "SORT", .shortname = "chat.mt.sort",		.chat_info = cf_sort},
  { .name = "ID", .shortname = "chat.mt.id",			.chat_info = cf_id},
  { .name = "SORTCONF", .shortname = "chat.mt.sortconf",	.chat_info = cf_sortconf},
  { .name = "CONTCLOSE", .shortname = "chat.mt.contclose",	.chat_info = cf_contclose},
  { .name = "PLC_MSG", .shortname = "chat.mt.plc_msg",		.chat_info = cf_plcmsg},
  { .name = NULL },
};



/* Method to find the next good field */
int chat_find_field_end(tvbuff_t *tvb, int offset, gint max_length, gboolean *last_field)
{
    /* look for CR */
    offset = tvb_find_guint8(tvb, offset, max_length, ',');

    if(offset != -1) {
      return offset;
    }else {
	/* couldn't find comma */
	*last_field = TRUE;
    }
  return offset;
}



static void dissect_chat_msg_from_glossary(char *mt, tvbuff_t *tvb, int offset, int length, proto_item *item)
{
  proto_tree *sub_tree;
  struct chat_field_info *info = NULL;
  struct chat_message_type *chat = NULL;
  int index = 0;
  int i = 0;
  gboolean last_field = FALSE;
  int next_pos = 0;
  int linelen = length;
  int current_pos = offset;
  
  printf("Finding match for chat message: [%s]\r\n", mt);
  
  if (mt == NULL)
    return;
  
  /* Find a match from the glossary */
  do{
      if (chat_mesage_table[i].name == NULL)
	return;
      if (strcmp(mt,chat_mesage_table[i].name)==0){
	info = chat_mesage_table[i].chat_info;
	chat = &chat_mesage_table[i];
	printf("Found match %s\r\n", mt);
	break;
      }
      i++;
  } while (TRUE);
  
  /* Found no subtree match */
  if (info == NULL)
    return;
  
    /*
   struct chat_field_info {
    int index_position;		
    int id; 			
    char name[50];
    char shortname[100];
    char description[120];
}; */
  sub_tree = proto_item_add_subtree(item, chat->id);
  do{
	  next_pos = chat_find_field_end(tvb, current_pos, linelen - (current_pos - offset), &last_field);
	  if (last_field == TRUE){
	    next_pos = offset + linelen;
	  }
	  
	  /* Reaches end of info index, nothing more to parse */
	  if (info[index].index_position == -1)
	    break;
	  
	  
	  proto_tree_add_item(sub_tree, info[index].id, tvb, current_pos, next_pos - current_pos , TRUE);

	  index++;
	  current_pos = next_pos + 1;
  }while (last_field != TRUE );
  return;
}



static void
dissect_chat_request(proto_tree *tree, tvbuff_t *tvb, int offset, int linelen)
{

	struct chat_message_type *chat = NULL;
	int i = 0;
	int index = 0;
	gboolean last_field = FALSE;
	int current_pos = offset;
	int next_pos = 0;
	int sub_next_pos = 0;
	proto_item *current_item;
	char * mt = NULL;
	
	do{
	  next_pos = chat_find_field_end(tvb, current_pos, linelen - (current_pos - offset), &last_field);
	  
	  if (last_field == TRUE){
	    printf("found end of line\r\n");
	    next_pos = offset + linelen;
	  }
	  
	  //if (next_pos < 0)
	    //break;
	   
	   /*
	  if (index<4){
	    if( (next_pos-current_pos)<=1)
	      goto next_decode;
	  } */
	  
	  switch (index){
	    case 0: 
	      proto_tree_add_item(tree, hf_chat_scn, tvb, current_pos, next_pos - current_pos , TRUE);
	      break; 
	    case 1: 
	      proto_tree_add_item(tree, hf_chat_sct, tvb, current_pos, next_pos - current_pos , TRUE);
	      break;
	    case 2: 
	      proto_tree_add_item(tree, hf_chat_rcn, tvb, current_pos, next_pos - current_pos , TRUE);
	      break;
	    case 3: 
	      proto_tree_add_item(tree, hf_chat_rct, tvb, current_pos, next_pos - current_pos , TRUE);
	      break;
	    case 4:
	      
	      current_item = proto_tree_add_item(tree, hf_chat_mt, tvb, current_pos, next_pos - current_pos , TRUE);
	      mt = tvb_get_string (wmem_packet_scope(), tvb, current_pos, next_pos - current_pos); 
	      
	      
	      printf("message type: %s, next_pos: %i, current_pos: %i\r\n", mt, next_pos, current_pos);

	      /* Find a match from the glossary */
	      chat = NULL;
	      do{
		  if (chat_mesage_table[i].name == NULL){
		    chat = NULL;
		    break;
		  }
		  if (strcmp(mt,chat_mesage_table[i].name)==0){
		    chat = &chat_mesage_table[i];
		    break;
		  }
		  i++;
	      } while (TRUE);
  
	      if (chat == NULL)
		  goto next_decode;

	      sub_next_pos = current_pos = next_pos + 1;
	      dissect_chat_msg_from_glossary(mt, tvb,sub_next_pos, linelen - (sub_next_pos - offset), current_item);

	      break;
	    case 5:
	      current_item = proto_tree_add_item(tree, hf_chat_payload, tvb, current_pos, linelen - current_pos , TRUE);
	      break;
	    default: break;
	  } /* switch */
	
next_decode:
	  index++;
	  current_pos = next_pos + 1;
	}while (last_field != TRUE || current_pos <= linelen);
	
}



static void
dissect_chat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *chat_tree, *ti;
	gint		offset = 0;
	gint		next_offset;
	int		linelen;
	int msg_number = 0;
	char in[30] = "IN ";
	char out[30] = "OUT ";




	//if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CHAT");



	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_chat, tvb, 0, -1, FALSE);
		chat_tree = proto_item_add_subtree(ti, ett_chat);

		/*
		 * Process the packet data, a line at a time.
		 */
		while (tvb_reported_length_remaining(tvb, offset) > 0)
		{
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
			if (next_offset == offset) {
				/*
				 * XXX - we really want the "show data a
				 * line at a time" loops in various
				 * dissectors to do reassembly and to
				 * throw an exception if there's no
				 * line ending in the current packet
				 * and we're not doing reassembly.
				 */
				break;
			}

			if (linelen != 0)
			{
				dissect_chat_request(chat_tree, tvb, offset, linelen);
				msg_number++;
				
			}
			offset = next_offset;
		}
	}


        sprintf(in,"i %i",msg_number);
	sprintf(out, "o %i", msg_number);
	
		//col_set_str(pinfo->cinfo, COL_INFO,
		//    (pinfo->match_port == pinfo->destport) ? out : in);
}




void
proto_register_chat(void)
{
	int i=0,j = 0;
	struct chat_field_info *info = NULL;
	struct chat_message_type *chat = NULL;
	hf_register_info * registry;
	hf_register_info * sub_registry;
	
	static gint *ett[] = {
		&ett_chat,
	};
	

	static hf_register_info hf[] = {	      
	  { &hf_chat_scn,
	    { "Sender Computer Name",            "chat.scn",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of request message", HFILL }},
	 { &hf_chat_sct,
	    { "Sender Computer Type",            "chat.sct",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of request message", HFILL }},
	 { &hf_chat_rcn,
	    { "Receiver Computer Name",          "chat.rcn",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of request message", HFILL }},
	  { &hf_chat_rct,
	    { "Receiver Computer Type",          "chat.rct",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of request message", HFILL }},
	   { &hf_chat_mt, { "Message Type",            "chat.mt",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of request message", HFILL }},
	       { &hf_chat_payload, { "Payload ",            "chatpayload",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of request message", HFILL }},
        };


	proto_chat = proto_register_protocol("Chat (SwiffDecoder)", "CHAT", "chat");
	

	 /* Find how many items */
	do{
	    if (chat_mesage_table[i].name == NULL)
	       break;
	    
	    chat = &chat_mesage_table[i];
	    info = chat->chat_info;
	    i++;
	} while (TRUE);
	
	registry = (hf_register_info *)malloc(sizeof(hf_register_info)*i);
	
	if (registry == NULL){
	   printf("Unable to allocate memory for chat dataset\r\n");
	   return;
	}
	
	
	i = 0;
	do{
	    if (chat_mesage_table[i].name == NULL)
	       break;
	    
	    chat = &chat_mesage_table[i];
	    info = chat->chat_info;
	
	    registry[i].p_id = &chat->id;
	    registry[i].hfinfo.name = chat->name;
	    registry[i].hfinfo.abbrev = chat->shortname;
	    registry[i].hfinfo.type = FT_STRING;
	    registry[i].hfinfo.display = 1;
	    registry[i].hfinfo.strings = NULL;
	    registry[i].hfinfo.bitmask = 0x0;
	    registry[i].hfinfo.blurb = chat->description;
	    registry[i].hfinfo.id = 0;
	    
	    
	    printf("Registering chat subtree name: %s\r\n", chat->name);
	    j = 0;
	    do {
	      if (info[j].index_position == -1)
		  break;
	      
	      sub_registry = (hf_register_info *)malloc(sizeof(hf_register_info));
	      sub_registry->p_id = &info[j].id;
	      sub_registry->hfinfo.name = info[j].name;
	      sub_registry->hfinfo.abbrev = info[j].shortname;
	      sub_registry->hfinfo.type = FT_STRING;
	      sub_registry->hfinfo.display = BASE_NONE;
	      sub_registry->hfinfo.strings = NULL;
	      sub_registry->hfinfo.bitmask = 0x0;
	      sub_registry->hfinfo.blurb = info[j].description;
	      sub_registry->hfinfo.id = 0;
	      proto_register_field_array(proto_chat, sub_registry, 1);
	      printf("                 token name: %s\r\n", info[j].shortname);
	      j++;
	    } while (TRUE);
	    
	    
	    
	    i++;
	} while (TRUE);
	
	
	
	
	


	proto_register_field_array(proto_chat, hf, array_length(hf));
	proto_register_field_array(proto_chat, registry, array_length(registry));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_chat(void)
{
	dissector_handle_t chat_handle;

	chat_handle = create_dissector_handle(dissect_chat, proto_chat);
	dissector_add_uint("tcp.port", TCP_PORT_chat, chat_handle);
	dissector_add_uint("tcp.port", 42301, chat_handle);
	dissector_add_uint("tcp.port", 7327, chat_handle);
	dissector_add_uint("tcp.port", TCP_PORT_DchatPROXY, chat_handle);
}
