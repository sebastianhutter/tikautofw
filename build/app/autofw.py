#!/usr/bin/env python3

"""
    simple python script to
    automatically create firewall rules based on docker containers
"""

import traceback
import logging
import schedule
import time
import rancher_api
import mikrotik
import autofwconfig

# configure logger
# http://docs.python-guide.org/en/latest/writing/logging/
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def scheduled_task():
    """
        get containers for which we shall create fw rules
        create, edit or remove the corresponding fw rules on the mikrotik system
    """

    # get all to be managed containers
    logger.info('Retrieve all containers for which we manage fw rules')
    containers_all = rancher.get_containers_with_label(config.docker_label_enable, 'true')

    # filter for only running containers
    containers = []
    if config.docker_check_running == 'true':
        for container in containers_all:
            if container['state'] == 'running':
                containers.append(container)
    else:
        # if option is not set to 'true' we will set firewall rules
        # for running and not running containers
        containers = containers_all

    #
    # add filter for running only containers here
    #
    #
    logger.info('Found ' + str(len(containers)) + ' containers.')

    # now from the containers get the nat firewall rules
    logger.info('Get all NAT rules from the containers')
    container_dstnat_rules = label_to_dstnat(containers)
    logger.info('Found {} valid rules in the container labels'.format(len(container_dstnat_rules)))
    # get the current dstnat rules form the mikrotik router
    logger.info('Retrieve dst nat rules from mikrotik which are managed by the autofw script')
    mikrotik_dstnat_rules = []
    for rule in router.get_dstnat_rules():
        if rule.comment:
            # we filter all dstnat rules with the comment which identifies
            # the rules managed by this script
            if config.mikrotik_comment in rule.comment:
                mikrotik_dstnat_rules.append(rule)
    logger.info('Retrieved {} dstnat rules from mikrotik'.format(len(mikrotik_dstnat_rules)))

    # now we keep it simple and stupid
    # first we iterate over all existing destination nat rules
    # if an existing rule matches a rule in the container defined rules we
    # will not delete the rule and we will not create it
    # matching is defined by
    # comment is the same
    # dst-port is the same
    # protocol is the same
    # in interface is the same
    # to-addresses is the same

    # if the rules dont match we will delete all managed rules from the mikrotik router
    # and then create the rules which are described in the container labels
    # we can not simply compare the container rule list and the mikrotik list and remove matching because the container
    #
    container_dstnat_rules_create = []

    mikrotik_dstnat_rules_persist = []
    logger.info('Compare container defined rules with mikrotik rules')
    for crule in container_dstnat_rules:
        # lets loop trough all container defined rules.
        # if they are not found in the mikrotik rules we will create them
        create_rule = True
        logger.debug("Container rule - id: {}, comment: {}, dst-port: {}, protocol: {}, in-interface: {}, to-addresses: {}".format(crule.id,crule.comment,crule.dstport,crule.protocol,crule.ininterface,crule.toaddresses))
        for mrule in mikrotik_dstnat_rules:
            # lets loop trough all the mikrotik rules.
            # if the mikrotik rule is equal to the container defined rule we dont have to create the rule
            # it already exists
            logger.debug("Mikrotik  rule - id: {}, comment: {}, dst-port: {}, protocol: {}, in-interface: {}, to-addresses: {}".format(mrule.id,mrule.comment,mrule.dstport,mrule.protocol,mrule.ininterface,mrule.toaddresses))
            if crule.comment == mrule.comment and crule.dstport == mrule.dstport and crule.protocol == mrule.protocol and crule.ininterface == mrule.ininterface and crule.toaddresses == mrule.toaddresses:
                logger.info("Found matching rule in mikrotik. Rule will not be deleted or created")
                # we wont create the rule
                create_rule = False
                # we temp. save the found mikrotik in an additional list
                mikrotik_dstnat_rules_persist.append(mrule)
                break

        # if the container defined rule does not exist add it to the list to be created
        if create_rule:
            container_dstnat_rules_create.append(crule)

    # now create the diff between the found mikrotik rules and the rules and the valid rules
    # couldnt make a comprehension work so I packed everything in a loop
    mikrotik_dstnat_rules_delete = []
    mikrotik_persist_set = set((x.id) for x in mikrotik_dstnat_rules_persist)
    for rule in mikrotik_dstnat_rules:
        if rule.id not in mikrotik_persist_set:
            mikrotik_dstnat_rules_delete.append(rule)

    logger.info('After comparing both rulesets we have {} rules to create and {} rules to delete'.format(len(container_dstnat_rules_create),len(mikrotik_dstnat_rules_delete)))

    # delete rules
    if len(mikrotik_dstnat_rules_delete) > 0:
        logger.info('Delete dstnat rules from mikrotik')
        for rule in mikrotik_dstnat_rules_delete:
            try:
                rule.remove_rule(router)
            except:
                logger.error("Unable to remove rule {} ({})".format(rule.id, rule.comment))

    # create rules
    if len(container_dstnat_rules_create) > 0:
        logger.info('Create dstnat rules as specified in the container labels')
        for rule in container_dstnat_rules_create:
            try:
                rule.add_rule(router)
            except:
                logger.error("Unable to add rule {} ({})".format(rule.id, rule.comment))


def label_to_dstnat(containers):
    """
        parse the docker labels from rancher and
        add create dstnat rules from the label
    """
    nat_rules = []
    # loop trough all available containers
    for container in containers:
        try:
            # check if the container has valid dstnat entries
            if config.docker_label_dstnat in container['labels']:
                nat_label_value = container['labels'][config.docker_label_dstnat]
                if not nat_label_value:
                    raise
                # a label can contain multiple rules which are separated by a :
                # so lets split the values
                for rule in nat_label_value.split(':'):
                    # now split the string into a dict which we can use to create dstnat objects
                    r = dict(x.split('=') for x in rule.split(','))
                    # add the comment from the config
                    r['comment'] = config.mikrotik_comment
                    if config.docker_label_dstnat_comment in container['labels']:
                        nat_label_comment = container['labels'][config.docker_label_dstnat_comment]
                        if nat_label_comment:
                            r['comment'] += ", " + nat_label_comment
                    # check if the toports parameter is set . if not set it to the same port as the dst. port
                    if not 'toports' in r:
                        r['toports'] = r['dstport']
                    # if no toaddress is specified set it to the ip address of the docker host
                    if not 'toaddresses' in r:
                        host = rancher.get_host_of_container(container_id=container['id'])
                        r['toaddresses'] = host['agentIpAddress']
                    # check if the actions parameter is set. if not set it to dst-nat
                    if not 'action' in r:
                        r['action'] = 'dst-nat'
                    # same for chain
                    if not 'chain' in r:
                        r['chain'] = 'dstnat'

                    # debug info
                    logger.debug(r)
                    nat_rules.append(mikrotik.DstNatFirewallRule(**r))
            else:
                raise
        except:
            logger.info('Container {} contains no valid nat rules'.format(container['name']))
    return nat_rules

def main():
    """
        main function
    """
    # initialize the configuration
    logger.info('Started autofw script')
    logger.info('Load configuration')
    global config
    config = autofwconfig.AutoFwConfig()

    # set the log level
    if config.loglevel == "info":
        logger.setLevel(logging.INFO)
    if config.loglevel == "debug":
        logger.setLevel(logging.DEBUG)
    # initialize the rancher metadata object

    logger.info('Connect to rancher api service')
    global rancher
    rancher = rancher_api.rancher_api(config.rancher_api_url, config.rancher_api_key, config.rancher_api_secret)
    # get a list of all docker containers which we should create firewall rules for
    logger.info('Get list of managed containers')

    # initialize the mikrotik object
    logger.info('Connect to mikrotik router')
    global router
    router = mikrotik.Mikrotik(config.mikrotik_address, config.mikrotik_user, config.mikrotik_pass)

    # start scheduler
    logger.info('Start scheduler and run update tasks')
    schedule.every(int(config.schedule)).seconds.do(scheduled_task)

    # loop and run scheduled tasks
    while 1:
        schedule.run_pending()
        time.sleep(1)

if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        logger.error(err)
        traceback.print_exc()
