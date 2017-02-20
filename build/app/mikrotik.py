#!/usr/bin/env python3

"""
    simple class to connect to the mikrotik router via ssh
    and configure its firewall
"""
import paramiko
import re
import logging
logger = logging.getLogger(__name__)

class Mikrotik(object):
    """
        connect and configure mikrotik router via ssh
    """

    def __init__(self, mikrotik_address, mikrotik_user, mikrotik_pass):
        self.address = mikrotik_address
        self.user = mikrotik_user
        self.password = mikrotik_pass
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.address, username=self.user, password=self.password, look_for_keys=False, allow_agent=False)
        except:
            raise

    def get_dstnat_rules(self):
        dstnat_rules = []
        for rule in self.get_allnat_rules():
            if rule.action == 'dst-nat':
                dstnat_rules.append(rule)
        return dstnat_rules

    def get_allnat_rules(self):
        """
            returns a list of all current active nat rules
        """

        # print all nat rules in machine friendly format
        cli = "/ip firewall nat print terse"
        stdin, stdout, stderr = self.ssh.exec_command(cli)

        # example output
        # flags: X = disabled, I = invalid, D = dynamic
        # id flg key=valye....
        # 13 XID chain=dstnat action=dst-nat to-addresses=192.168.30.102 protocol=tcp in-interface=sfp1 dst-port=8200
        # the regular exp. creates one group for the id, one group for each flag and one group containing all conigs
        match_pattern='^\s*(\d+)\s(\w?)(\w?)(\w?)\s+(\w+?=.*)'
        # we know that the comment field is the first field before the chain field (if its set)
        comment_pattern='^comment=(.+)\schain='
        # find everything like key=value
        parameter_pattern="([\w,-]+)=([\w,\.,-]+)+"
        nat_rules = []
        for line in stdout:
            # if line is not empty
            if not line or line != '\r\n':
                parsed_line = re.findall(match_pattern, line.replace(' \r\n',''))
                parsed_line = parsed_line[0]
                # a parsed line looks now soemthing like this
                # ('0', '', '', '', 'chain=srcnat action=accept src-address=192.168.30.0/24 dst-address=172.17.0.0/24 log=no')

                # lets get the values out of the parsed string
                rule = {}
                rule['id'] = parsed_line[0]
                # we ignore the flags atm
                # get the comment if its defined
                comment = re.findall(comment_pattern, parsed_line[4])
                # a found comment looks something like this
                # ['plex port forward']
                if comment:
                    rule['comment'] = comment[0]

                # now get all the other parameters
                paramter_matches = re.finditer(parameter_pattern, parsed_line[4])
                # iterate over all found matches
                # a match object looks something like this
                # <_sre.SRE_Match object; span=(28, 55), match='to-addresses=192.168.30.102'>
                # and gives me 3 groups ->
                # group 0 = key=value
                # group 1 = key
                # group 2 = value
                for match in paramter_matches:
                    # i was not able to properly filter the comment key/value out so
                    # lets filter again on group level
                    if match.group(1) != 'comment':
                        # lets add the different parameters to the natrule dict
                        # remove - in the key name
                        rule[match.group(1).replace('-','')] = match.group(2)

                # log the dict
                logger.debug(rule)
                nat_rules.append(DstNatFirewallRule(**rule))
        return nat_rules

class DstNatFirewallRule(object):
    """
        represents a dst nat firewall rule
    """

    def __init__(self, protocol=None, dstport=None, toports=None, comment=None,
                 toaddresses=None, srcaddress=None, dstaddress=None, log=None,
                 ininterface=None, outinterface=None, chain=None, action=None, logprefix=None, id=None):
        """
            simplified nat rule
            we only allow the very basic nat rule config
            chain, to-addresses, protocol, in-interface, dst-port and log-prefix
        """
        self.id = id
        self.protocol = protocol
        self.dstport = dstport
        self.toports = toports
        self.toaddresses = toaddresses
        self.srcaddress = srcaddress
        self.comment = comment
        self.ininterface = ininterface
        self.chain =  chain
        self.logprefix = logprefix
        self.action = action

    def add_rule(self, mikrotik_router):
        """
            this function creates a a new dstnat rule
        """
        logger.debug('Create dstnat rule with dst-port {} ({}) on  mikrotik router {}'.format(self.dstport, self.comment, mikrotik_router.address))

        try:
            # base command line.
            # will be extended by some values
            cli = "/ip firewall nat add"

            # those are the required values to be set
            # (not quite correct -> different combinations allow for different values. for example if a dst-address is specified a dst-port is not necessary)
            if not self.dstport:
                raise ValueError("no dst-port specified for dstnat rule")
            if not self.toaddresses:
                raise ValueError("no to-addresses specified for dstnat rule")
            cli = cli + " dst-port={} to-addresses={}".format(self.dstport,self.toaddresses)

            # now add some optional values
            if self.protocol:
                cli = cli + " protocol={}".format(self.protocol)
            if self.toports:
                cli = cli + " to-ports={}".format(self.toports)
            if self.srcaddress:
                cli = cli + " src-address={}".format(self.srcaddress)
            if self.ininterface:
                cli = cli + " in-interface={}".format(self.ininterface)
            if self.chain:
                cli = cli + " chain={}".format(self.chain)
            if self.logprefix:
                cli = cli + " log-prefix={}".format(self.logprefix)
            if self.action:
                cli = cli + " action={}".format(self.action)
            if self.comment:
                cli = cli + " comment=\"{}\"".format(self.comment)

            logger.debug("add cli: {}".format(cli))
            # create the rule
            stdin, stdout, stderr = mikrotik_router.ssh.exec_command(cli)
        except:
            raise

    def remove_rule(self, mikrotik_router):
        """
            this function removes a dstnat rule by id
        """
        logger.debug('Delete rule id {} ({}) from mikrotik router {}'.format(self.id, self.comment, mikrotik_router.address))
        try:
            if not self.id:
                raise ValueError("Invalid rule id")

            cli = "/ip firewall nat remove {}".format(self.id)
            stdin, stdout, stderr = mikrotik_router.ssh.exec_command(cli)
        except:
            raise