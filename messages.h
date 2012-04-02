/*
 * Copyright 2012 Ricardo Garcia Gonzalez
 * 
 * This file is part of saircd.
 * 
 * saircd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * saircd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with saircd.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * messages.h - IRC Messages.
 */
#ifndef _MESSAGES_H_
#define _MESSAGES_H_

#define MAX_MESSAGE_LEN 512
#define MESSAGE_BUFFER_SIZE (MAX_MESSAGE_LEN + 1)

#define MAX_MESSAGE_PARAMS 15
#define MAX_TOKENS (MAX_MESSAGE_PARAMS + 2)

/*
 * Numeric replies.
 */

/* Command responses. */
#define RPL_WELCOME		(1)
#define RPL_YOURHOST		(2)
#define RPL_CREATED		(3)
#define RPL_MYINFO		(4)
#define	RPL_BOUNCE		(5)
#define RPL_USERHOST		(302)
#define RPL_ISON		(303)
#define	RPL_AWAY		(301)
#define RPL_UNAWAY		(305)
#define RPL_NOWAWAY		(306)
#define	RPL_WHOISUSER		(311)
#define	RPL_WHOISSERVER		(312)
#define RPL_WHOISOPERATOR	(313)
#define RPL_WHOISIDLE		(317)
#define	RPL_ENDOFWHOIS		(318)
#define RPL_WHOISCHANNELS	(319)
#define RPL_WHOWASUSER		(314)
#define RPL_ENDOFWHOWAS		(369)
#define RPL_LISTSTART		(321)
#define RPL_LIST		(322)
#define RPL_LISTEND		(323)
#define RPL_UNIQOPIS		(325)
#define RPL_CHANNELMODEIS	(324)
#define RPL_NOTOPIC		(331)
#define RPL_TOPIC		(332)
#define RPL_INVITING		(341)
#define RPL_SUMMONING		(342)
#define RPL_INVITELIST		(346)
#define RPL_ENDOFINVITELIST	(347)
#define RPL_EXCEPTLIST		(348)
#define RPL_ENDOFEXCEPTLIST	(349)
#define RPL_VERSION		(351)
#define RPL_WHOREPLY		(352)
#define RPL_ENDOFWHO		(315)
#define RPL_NAMREPLY		(353)
#define RPL_ENDOFNAMES		(366)
#define RPL_LINKS		(364)
#define RPL_ENDOFLINKS		(365)
#define RPL_BANLIST		(367)
#define RPL_ENDOFBANLIST	(368)
#define RPL_INFO		(371)
#define RPL_ENDOFINFO		(374)
#define RPL_MOTDSTART		(375)
#define RPL_MOTD		(372)
#define RPL_ENDOFMOTD		(376)
#define RPL_YOUREOPER		(381)
#define RPL_REHASHING		(382)
#define RPL_YOURESERVICE	(383)
#define RPL_TIME		(391)
#define RPL_USERSSTART		(392)
#define RPL_USERS		(393)
#define RPL_ENDOFUSERS		(394)
#define RPL_NOUSERS		(395)
#define RPL_TRACELINK		(200)
#define RPL_TRACECONNECTING	(201)
#define RPL_TRACEHANDSHAKE	(202)
#define RPL_TRACEUNKNOWN	(203)
#define RPL_TRACEOPERATOR	(204)
#define RPL_TRACEUSER		(205)
#define RPL_TRACESERVER		(206)
#define RPL_TRACESERVICE	(207)
#define RPL_TRACENEWTYPE	(208)
#define RPL_TRACECLASS		(209)
#define RPL_TRACERECONNECT	(210)
#define RPL_TRACELOG		(261)
#define RPL_TRACEEND		(262)
#define RPL_STATSLINKINFO	(211)
#define RPL_STATSCOMMANDS	(212)
#define RPL_ENDOFSTATS		(219)
#define RPL_STATSUPTIME		(242)
#define RPL_STATSOLINE		(243)
#define RPL_UMODEIS		(221)
#define RPL_SERVLIST		(234)
#define RPL_SERVLISTEND		(235)
#define RPL_LUSERCLIENT		(251)
#define RPL_LUSEROP		(252)
#define RPL_LUSERUNKNOWN	(253)
#define RPL_LUSERCHANNELS	(254)
#define RPL_LUSERME		(255)
#define RPL_ADMINME		(256)
#define RPL_ADMINLOC1		(257)
#define RPL_ADMINLOC2		(258)
#define RPL_ADMINEMAIL		(259)
#define RPL_TRYAGAIN		(263)

/* Error replies. */
#define ERR_NOSUCHNICK		(401)
#define ERR_NOSUCHSERVER	(402)
#define ERR_NOSUCHCHANNEL	(403)
#define ERR_CANNOTSENDTOCHAN	(404)
#define ERR_TOOMANYCHANNELS	(405)
#define ERR_WASNOSUCHNICK	(406)
#define ERR_TOOMANYTARGETS	(407)
#define ERR_NOSUCHSERVICE	(408)
#define ERR_NOORIGIN		(409)
#define ERR_NORECIPIENT		(411)
#define ERR_NOTEXTTOSEND	(412)
#define ERR_NOTOPLEVEL		(413)
#define ERR_WILDTOPLEVEL	(414)
#define ERR_BADMASK		(415)
#define ERR_TOOMANYMATCHES	(416)
#define ERR_UNKNOWNCOMMAND	(421)
#define ERR_NOMOTD		(422)
#define ERR_NOADMININFO		(423)
#define ERR_FILEERROR		(424)
#define ERR_NONICKNAMEGIVEN	(431)
#define ERR_ERRONEUSNICKNAME	(432)
#define ERR_NICKNAMEINUSE	(433)
#define ERR_NICKCOLLISION	(436)
#define ERR_UNAVAILRESOURCE	(437)
#define ERR_USERNOTINCHANNEL	(441)
#define ERR_NOTONCHANNEL	(442)
#define ERR_USERONCHANNEL	(443)
#define ERR_NOLOGIN		(444)
#define ERR_SUMMONDISABLED	(445)
#define ERR_USERSDISABLED	(446)
#define ERR_NOTREGISTERED	(451)
#define ERR_NEEDMOREPARAMS	(461)
#define ERR_ALREADYREGISTERED	(462)
#define ERR_NOPERMFORHOST	(463)
#define ERR_PASSWDMISMATCH	(464)
#define ERR_YOUREBANNEDCREEP	(465)
#define ERR_YOUWILLBEBANNED	(466)
#define ERR_KEYSET		(467)
#define ERR_CHANNELISFULL	(471)
#define ERR_UNKNOWNMODE		(472)
#define ERR_INVITEONLYCHAN	(473)
#define ERR_BANNEDFROMCHAN	(474)
#define ERR_BADCHANNELKEY	(475)
#define ERR_BADCHANMASK		(476)
#define ERR_NOCHANMODES		(477)
#define ERR_BANLISTFULL		(478)
#define ERR_NOPRIVILEGES	(481)
#define ERR_CHANOPRIVSNEEDED	(482)
#define ERR_CANTKILLSERVER	(483)
#define ERR_RESTRICTED		(484)
#define ERR_UNIQOPPRIVSNEEDED	(485)
#define ERR_NOOPERHOST		(491)
#define ERR_UMODEUNKNOWNFLAG	(501)
#define ERR_USERSDONTMATCH	(502)

/* Reserved numerics. */
#define RPL_SERVICEINFO		(231)
#define RPL_ENDOFSERVICES	(232)
#define RPL_SERVICE		(233)
#define RPL_NONE		(300)
#define RPL_WHOISCHANOP		(316)
#define RPL_KILLDONE		(361)
#define RPL_CLOSING		(362)
#define RPL_CLOSEEND		(363)
#define RPL_INFOSTART		(373)
#define RPL_MYPORTIS		(384)
#define RPL_STATSCLINE		(213)
#define RPL_STATSNLINE		(214)
#define RPL_STATSILINE		(215)
#define RPL_STATSKLINE		(216)
#define RPL_STATSQLINE		(217)
#define RPL_STATSYLINE		(218)
#define RPL_STATSVLINE		(240)
#define RPL_STATSLLINE		(241)
#define RPL_STATSHLINE		(244)
#define RPL_STATSSLINE		(245)
#define RPL_STATSPING		(246)
#define RPL_STATSBLINE		(247)
#define RPL_STATSDLINE		(250)
#define ERR_NOSERVICEHOST	(492)

/*
 * Client commands.
 */

#define CMD_BASE_NUMBER		(10000)
#define CMD_TOP_NUMBER		(10050)

/* Connection registration. */
#define CMD_PASS		(10001)
#define CMD_NICK		(10002)
#define	CMD_USER		(10003)
#define	CMD_OPER		(10004)
#define CMD_MODE		(10005)
#define CMD_SERVICE		(10006)
#define CMD_QUIT		(10007)
#define CMD_SQUIT		(10008)

/* Channel operations. */
#define CMD_JOIN		(10009)
#define CMD_PART		(10010)
/* Already defined for the connection registration. */
/*#define CMD_MODE		(10011) */
#define CMD_TOPIC		(10012)
#define CMD_NAMES		(10013)
#define CMD_LIST		(10014)
#define CMD_INVITE		(10015)
#define CMD_KICK		(10016)

/* Sending messages. */
#define CMD_PRIVMSG		(10017)
#define CMD_NOTICE		(10018)

/* Server queries and commands. */
#define CMD_MOTD		(10019)
#define CMD_LUSERS		(10020)
#define CMD_VERSION		(10021)
#define CMD_STATS		(10022)
#define CMD_LINKS		(10023)
#define CMD_TIME		(10024)
#define CMD_CONNECT		(10025)
#define CMD_TRACE		(10026)
#define CMD_ADMIN		(10027)
#define CMD_INFO		(10028)

/* Service Query and Commands. */
#define CMD_SERVLIST		(10029)
#define CMD_SQUERY		(10030)

/* User-based queries. */
#define CMD_WHO			(10031)
#define CMD_WHOIS		(10032)
#define CMD_WHOWAS		(10033)

/* Miscellaneous messages. */
#define CMD_KILL		(10034)
#define CMD_PING		(10035)
#define CMD_PONG		(10036)
#define CMD_ERROR		(10037)

/* Optional features. */
#define CMD_AWAY		(10038)
#define CMD_REHASH		(10039)
#define CMD_DIE			(10040)
#define CMD_RESTART		(10041)
#define CMD_SUMMON		(10042)
#define CMD_USERS		(10043)
#define CMD_WALLOPS		(10044)
#define CMD_USERHOST		(10045)
#define CMD_ISON		(10046)

/* 
 * Command restrictions and constants.
 */
#define MAX_NICKNAME_LEN	(9)
#define NICKNAME_BUFFER_SIZE	(MAX_NICKNAME_LEN + 1)

#define TYPE_NICK		(0)
#define TYPE_CHAN		(1)
#define TYPE_OTHER		(2)

#define MAX_CHANNEL_LEN		(50)
#define CHANNEL_BUFFER_SIZE	(MAX_CHANNEL_LEN + 1)

#define MAX_TARGETS		(8)
#define MAX_CHAN_MODE_PARAMS	(3)
#define MAX_USERHOST_NICKNAMES	(5)

/* Internal errors that do not generate a reply are below zero. */
#define PARSE_ERROR		(-1)

/*
 * struct tokens - List of words in an IRC line.
 *
 * This struct represents the list of tokens (words) in an IRC protocol line.
 * Each token can be as long as the whole line, and the number of tokens is
 * limited by the RFC to be MAX_TOKENS. The counter represents how many tokens
 * are being held in the token array, and the tokens are stored in that array,
 * from zero to the counter minus one.
 *
 * Use tokenize() to transform an IRC protocol line to this structured form.
 */
struct tokens {
	int counter;
	char token[MAX_TOKENS][MESSAGE_BUFFER_SIZE];
};

/*
 * The following enums and structs are auxiliar and used in struct command.
 */
enum action_flag { NO_ACTION, ACTION_ADD, ACTION_REMOVE };

enum chan_mode_with_parameters {
	MODE_OPER,
	MODE_VOICE,
	MODE_KEY,
	MODE_LIMIT,
	MODE_BANMASK,
	MODE_EXCEPTMASK,
	MODE_INVITEMASK
};

struct chan_mode_arg {
	enum chan_mode_with_parameters mode;
	enum action_flag action;
	char param[MESSAGE_BUFFER_SIZE];
};

/*
 * struct command - Structured representation of an IRC client command.
 *
 * This structure represents an IRC client command. Hence, it has an optional
 * prefix, a command number and the command arguments. The command arguments
 * are stored inside the "args" union. To know which member of this union is
 * applicable, check "number". Inside each one of those structs, the command
 * parameters are held. They vary from command to command.
 *
 * Use parse_tokens() to transform a struct tokens to this struct.
 */
struct command {
	char prefix[MESSAGE_BUFFER_SIZE];
	int number;
	union _args {
		/* CMD_PASS */
		struct _cmd_pass {
			char password[MESSAGE_BUFFER_SIZE];
		} cmd_pass;

		/* CMD_NICK */
		struct _cmd_nick {
			char nickname[NICKNAME_BUFFER_SIZE];
		} cmd_nick;

		/* CMD_USER */
		struct _cmd_user {
			char user[MESSAGE_BUFFER_SIZE];
			int mode;
			char realname[MESSAGE_BUFFER_SIZE];
		} cmd_user;

		/* CMD_OPER */
		struct _cmd_oper {
			char name[MESSAGE_BUFFER_SIZE];
			char password[MESSAGE_BUFFER_SIZE];
		} cmd_oper;

		/* CMD_MODE */
		struct _cmd_mode {
			int mode_type;
			union _mode_args {
				/* TYPE_NICK */
				struct _type_nick {
					char nickname[NICKNAME_BUFFER_SIZE];
					enum action_flag away;
					enum action_flag invisible;
					enum action_flag wallops;
					enum action_flag restricted;
					enum action_flag net_operator;
					enum action_flag local_operator;
					enum action_flag notices;
				} type_nick;

				/* TYPE_CHAN */
				struct _type_chan {
					/*
					 * Channel modes are divided in two
					 * groups: the ones that don't take
					 * parameters and the ones that do, of
					 * which only three are allowed in a
					 * mode command. The ones that do not
					 * take parameters have a direct flag,
					 * and the ones that take parameters
					 * are stored in an array.
					 */
					char channel[CHANNEL_BUFFER_SIZE];
					enum action_flag anonymous;
					enum action_flag invite_only;
					enum action_flag moderated;
					enum action_flag no_outside;
					enum action_flag quiet;
					enum action_flag private_m;
					enum action_flag secret;
					enum action_flag topic;
					int num_others;
					struct chan_mode_arg others[MAX_CHAN_MODE_PARAMS];
					char unknown_modes[MESSAGE_BUFFER_SIZE];
				} type_chan;
			} mode_args;
		} cmd_mode;

		/* CMD_SERVICE */
		struct _cmd_service {
			char nickname[NICKNAME_BUFFER_SIZE];
			char distribution[MESSAGE_BUFFER_SIZE];
			char type[MESSAGE_BUFFER_SIZE];
			char info[MESSAGE_BUFFER_SIZE];
		} cmd_service;

		/* CMD_QUIT */
		struct _cmd_quit {
			char message[MESSAGE_BUFFER_SIZE];
		} cmd_quit;

		/* CMD_SQUIT */
		struct _cmd_squit {
			char server[MESSAGE_BUFFER_SIZE];
			char comment[MESSAGE_BUFFER_SIZE];
		} cmd_squit;

		/* CMD_JOIN */
		struct _cmd_join {
			int num_channels;
			char channels[MAX_TARGETS][CHANNEL_BUFFER_SIZE];
			int num_keys;
			char keys[MAX_TARGETS][MESSAGE_BUFFER_SIZE];
		} cmd_join;

		/* CMD_PART */
		struct _cmd_part {
			int num_channels;
			char channels[MAX_TARGETS][CHANNEL_BUFFER_SIZE];
			char message[MESSAGE_BUFFER_SIZE];
		} cmd_part;

		/* CMD_TOPIC */
		struct _cmd_topic {
			char channel[MESSAGE_BUFFER_SIZE];
			int topic_given;
			char topic[MESSAGE_BUFFER_SIZE];
		} cmd_topic;

		/* CMD_NAMES and CMD_LIST */
		struct _cmd_names_list {
			int num_channels;
			char channels[MAX_TARGETS][CHANNEL_BUFFER_SIZE];
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_names_list;

		/* CMD_INVITE */
		struct _cmd_invite {
			char nickname[NICKNAME_BUFFER_SIZE];
			char channel[CHANNEL_BUFFER_SIZE];
		} cmd_invite;

		/* CMD_KICK */
		struct _cmd_kick {
			int num_channels;
			char channels[MAX_TARGETS][CHANNEL_BUFFER_SIZE];
			int num_nicknames;
			char nicknames[MAX_TARGETS][NICKNAME_BUFFER_SIZE];
			char comment[MESSAGE_BUFFER_SIZE];
		} cmd_kick;

		/* CMD_PRIVMSG */
		struct _cmd_privmsg {
			int target_type;
			union _privmsg_target {
				/* TYPE_NICK */
				char nickname[NICKNAME_BUFFER_SIZE];
				/* TYPE_CHAN */
				char channel[CHANNEL_BUFFER_SIZE];
			} target;
			char text[MESSAGE_BUFFER_SIZE];
		} cmd_privmsg;

		/* CMD_NOTICE */
		struct _cmd_notice {
			int target_type;
			union _notice_target {
				/* TYPE_NICK */
				char nickname[NICKNAME_BUFFER_SIZE];
				/* TYPE_CHAN */
				char channel[CHANNEL_BUFFER_SIZE];
			} target;
			char text[MESSAGE_BUFFER_SIZE];
		} cmd_notice;

		/* CMD_MOTD */
		struct _cmd_motd {
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_motd;

		/* CMD_LUSERS */
		struct _cmd_lusers {
			char mask[MESSAGE_BUFFER_SIZE];
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_lusers;

		/* CMD_VERSION */
		struct _cmd_version {
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_version;

		/* CMD_STATS */
		struct _cmd_stats {
			char query;
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_stats;

		/* CMD_LINKS */
		struct _cmd_links {
			char remote_server[MESSAGE_BUFFER_SIZE];
			char server_mask[MESSAGE_BUFFER_SIZE];
		} cmd_links;

		/* CMD_TIME */
		struct _cmd_time {
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_time;

		/* CMD_CONNECT */
		struct _cmd_connect {
			char target_server[MESSAGE_BUFFER_SIZE];
			int port;
			char remote_server[MESSAGE_BUFFER_SIZE];
		} cmd_connect;

		/* CMD_TRACE */
		struct _cmd_trace {
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_trace;

		/* CMD_ADMIN */
		struct _cmd_admin {
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_admin;

		/* CMD_INFO */
		struct _cmd_info {
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_info;

		/* CMD_SERVLIST */
		struct _cmd_servlist {
			char mask[MESSAGE_BUFFER_SIZE];
			char type[MESSAGE_BUFFER_SIZE];
		} cmd_servlist;

		/* CMD_SQUERY */
		struct _cmd_squery {
			char servicename[MESSAGE_BUFFER_SIZE];
			char text[MESSAGE_BUFFER_SIZE];
		} cmd_squery;

		/* CMD_WHO */
		struct _cmd_who {
			int target_type;
			union _who_target {
				/* TYPE_NICK */
				char nickname[NICKNAME_BUFFER_SIZE];
				/* TYPE_CHAN */
				char channel[CHANNEL_BUFFER_SIZE];
				/* TYPE_OTHER */
				char mask[MESSAGE_BUFFER_SIZE];
			} target;
			int o;
		} cmd_who;

		/* CMD_WHOIS */
		struct _cmd_whois {
			char target[MESSAGE_BUFFER_SIZE];
			int num_nicknames;
			char nicknames[MAX_TARGETS][MESSAGE_BUFFER_SIZE];
			char orig_query[MESSAGE_BUFFER_SIZE];
		} cmd_whois;

		/* CMD_WHOWAS */
		struct _cmd_whowas {
			int num_nicknames;
			char nicknames[MAX_TARGETS][MESSAGE_BUFFER_SIZE];
			int count;
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_whowas;

		/* CMD_KILL */
		struct _cmd_kill {
			char nickname[MESSAGE_BUFFER_SIZE];
			char comment[MESSAGE_BUFFER_SIZE];
		} cmd_kill;

		/* CMD_PING or CMD_PONG */
		struct _cmd_ping_pong {
			char server1[MESSAGE_BUFFER_SIZE];
			char server2[MESSAGE_BUFFER_SIZE];
		} cmd_ping_pong;

		/* CMD_ERROR */
		struct _cmd_error {
			char error[MESSAGE_BUFFER_SIZE];
		} cmd_error;

		/* CMD_AWAY */
		struct _cmd_away {
			char text[MESSAGE_BUFFER_SIZE];
		} cmd_away;

		/* CMD_REHASH */
		struct _cmd_rehash {
		} cmd_rehash;

		/* CMD_DIE */
		struct _cmd_die {
		} cmd_die;

		/* CMD_RESTART */
		struct _cmd_restart {
		} cmd_restart;

		/* CMD_SUMMON */
		struct _cmd_summon {
			char user[MESSAGE_BUFFER_SIZE];
			char target[MESSAGE_BUFFER_SIZE];
			char channel[CHANNEL_BUFFER_SIZE];
		} cmd_summon;

		/* CMD_USERS */
		struct _cmd_users {
			char target[MESSAGE_BUFFER_SIZE];
		} cmd_users;

		/* CMD_WALLOPS */
		struct _cmd_wallops {
			char text[MESSAGE_BUFFER_SIZE];
		} cmd_wallops;

		/* CMD_USERHOST */
		struct _cmd_userhost {
			int num_nicknames;
			char nicknames[MAX_USERHOST_NICKNAMES][NICKNAME_BUFFER_SIZE];
		} cmd_userhost;

		/* CMD_ISON */
		struct _cmd_ison {
			int num_nicknames;
			char nicknames[MAX_MESSAGE_PARAMS][NICKNAME_BUFFER_SIZE];
		} cmd_ison;

	} args;
};

/*
 * init_tokens - Reset a struct tokens.
 *
 * The function needs a pointer to a struct tokens and resets its data to
 * contain no tokens.
 */
void init_tokens(struct tokens *t);

/*
 * tokenize - Transform an IRC client line to struct tokens.
 *
 * This function needs a line and an ouput struct tokens, and will extract the
 * words from this line and store them in the struct tokens passed as the
 * second argument.
 *
 * The return value is a negative number in case of errors. Otherwise, the
 * number of output tokens is returned, and is the same value as t->counter.
 */
int tokenize(const char *line, struct tokens *t);

/*
 * init_command - Reset a struct command.
 *
 * The function needs a pointer to a struct command and resets its data to
 * contain no command. This means the prefix will be the empty string and the
 * command number will be set to zero, which is an invalid command number,
 * among other possible actions.
 */
void init_command(struct command *c);

/*
 * parse_tokens - Parse a struct tokens into a struct command.
 *
 * This function needs an input struct tokens and populates a struct command
 * with the appropriate values representing the IRC client command, hence
 * parsing the tokens.
 *
 * The return value will be zero in case of success and nonzero otherwise. When
 * errors are found in IRC client commands, sometimes an error code needs to be
 * returned to the client, and sometimes the error is to be silently ignored.
 * If the return value is nonzero AND negative, it's a silent error (e.g.
 * PARSE_ERROR). Otherwise, it will correspond to an error value specified by
 * the protocol, to be returned to the client. See the ERR_* constants for
 * error replies.
 */
int parse_tokens(const struct tokens *t, struct command *c);

/*
 * messages_free - Free messages parsing module memory.
 *
 * This function frees memory allocated by usage of other module functions.
 */
void messages_free(void);

#endif
