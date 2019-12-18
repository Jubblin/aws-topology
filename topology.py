#!/usr/bin/env python
import boto3
import logging
from py2neo import Graph, Node, Relationship
import time



def convert_time(seconds):
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "%d:%02d:%02d" % (hour, minutes, seconds)


def check_key(dictionary, key):
    if key in dictionary.keys():
        return dictionary[key]
    else:
        return "Unknown"


def find_name_tag(tags):
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return ""


def find_tags(*args):
    if args[1].__contains__('Tags'):
        name = find_name_tag(args[1]['Tags'])
        args[0].debug('Tag: ' + name + " found")
    elif args[1].__contains__('SubnetId'):
        name = args[1]['SubnetId']
        args[0].debug('name value configured as SubnetId: ' + name)
    elif args[1].__contains__('elcId'):
        name = args[1]['elcId']
        args[0].debug('name value configured as elcId: ' + name)
    else:
        name = ""
    return name


def find_node(*args, **kwargs):
    start_timer = time.time()
    node = args[0].find_one(**kwargs)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")
    return node


def create_node(*args, **kvargs):
    start_timer = time.time()
    tx = args[0].begin()
    graph_node = Node(args[2], **kvargs)
    tx.merge(graph_node)
    tx.commit()
    args[1].debug('Create Graph node: ' + args[2] + " " + str(kvargs))
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")
    return graph_node


def create_relationship(*args, **kvargs):
    start_timer = time.time()
    tx = args[0].begin()
    if len(kvargs) > 0:
        args[1].debug('Create Graph Relationship: ' + args[2]['Name'] + " " + args[3] + " " + args[4]['Name'] + " " +
                      str(kvargs))
        relationship = Relationship(args[2], args[3], args[4], **kvargs)
    else:
        name = find_tags(args[1], args[2])
        args[1].debug('Create Graph Relationship: ' + name + " " + args[3] + " " + args[4]['Name'])
        relationship = Relationship(args[2], args[3], args[4])
    tx.merge(relationship)
    tx.commit()
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")
    return relationship


def create_subnets(*args):
    start_timer = time.time()
    subnets_array = []
    subnets = args[4].describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [args[3]]}])
    if subnets['Subnets']:
        for subnet in subnets['Subnets']:
            graph_az = create_node(args[0], args[1], "AvailabilityZone", Name=subnet['AvailabilityZone'],
                                   AvailabilityZoneId=subnet['AvailabilityZoneId'])
            name = find_tags(args[1], subnet)
            graph_subnet = create_node(args[0], args[1], "Subnet",
                                       SubnetId=subnet['SubnetId'],
                                       Name=name,
                                       az=subnet['AvailabilityZone'],
                                       cidr=subnet['CidrBlock'],
                                       VpcId=subnet['VpcId'],
                                       IsDefault=subnet['DefaultForAz'])
            if graph_subnet is not None:
                create_relationship(args[0], args[1], graph_subnet, "BELONGS", graph_az)
            if graph_az is not None:
                create_relationship(args[0], args[1], graph_az, "BELONGS", args[2])
            subnets_array.append(graph_subnet)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")
    return subnets_array


def create_igws(*args):
    start_timer = time.time()
    igws_array = []
    igws = args[3].describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [args[2]]}])
    if igws['InternetGateways']:
        for igw in igws['InternetGateways']:
            name = find_tags(args[1], igw)
            graph_igw = create_node(args[0], args[1], "IGW", igwId=igw['InternetGatewayId'],
                                    VpcId=igw['Attachments'][0]['VpcId'], Name=name, IsDefault=args[4])
            igws_array.append(graph_igw)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")
    return igws_array


def create_nat_gws(*args):
    start_timer = time.time()
    ngws_array = []
    ngws = args[3].describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [args[2]]}])
    if ngws['NatGateways']:
        for ngw in ngws['NatGateways']:
            name_tag = find_tags(args[1], ngw)
            if name_tag == '':
                name_tag = ngw['NatGatewayId']
            graph_ngw = create_node(args[0], args[1], "NATGW", ngwId=ngw['NatGatewayId'], SubnetId=ngw['SubnetId'],
                                    Name=name_tag, IsDefault=args[4])
            ngws_array.append(graph_ngw)
            find_eip = find_node(args[0], args[1], label="EIP", property_key='AllocationId',
                                 property_value=ngw['NatGatewayAddresses'][0]['AllocationId'])
            if find_eip is not None:
                create_relationship(args[0], args[1], find_eip, "BELONGS", graph_ngw)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")
    return ngws_array


def create_vpc(*args):
    start_timer = time.time()
    vpcs = args[3].describe_vpcs()
    if vpcs['Vpcs']:
        for vpc in vpcs['Vpcs']:
            name = find_tags(args[1], vpc)
            graph_vpc = create_node(args[0], args[1], "VPC", vpcId=vpc['VpcId'], Name=name, cidr=vpc['CidrBlock'],
                                    IsDefault=vpc['IsDefault'])

            subnets = create_subnets(args[0], args[1], args[2], vpc['VpcId'], args[3], vpc['IsDefault'])
            igws = create_igws(args[0], args[1], vpc['VpcId'], args[3], vpc['IsDefault'])
            ngws = create_nat_gws(args[0], args[1],  vpc['VpcId'], args[3], vpc['IsDefault'])

            create_relationship(args[0], args[1], graph_vpc, "BELONGS", args[2])
            for subnet in subnets:
                create_relationship(args[0], args[1], subnet, "BELONGS", graph_vpc)
            for igw in igws:
                create_relationship(args[0], args[1], igw, "ATTACHED", graph_vpc)
            for ngw in ngws:
                graph_subnet = find_node(args[0], args[1], label="Subnet", property_key='SubnetId',
                                         property_value=ngw['SubnetId'])
                create_relationship(args[0], args[1], ngw, "BELONGS", graph_subnet)

    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def find_attachments(volume):
    attachments = []
    for attachment in volume['Attachments']:
        attachments.append(attachment)
    return attachments


def create_ec2_volumes(*args):
    start_timer = time.time()
    volumes = args[2].describe_volumes()
    for volume in volumes['Volumes']:
        attachments = find_attachments(volume)
        name_tag = find_tags(args[1], volume)
        if name_tag == '':
            name_tag = volume['VolumeId']
        if len(attachments) >= 1:
            create_node(args[0], args[1], "Volumes", Name=name_tag, AvailabilityZone=volume['AvailabilityZone'],
                        Size=volume['Size'], VolumeId=volume['VolumeId'], VolumeType=volume['VolumeType'],
                        Encrypted=volume['Encrypted'], DeviceName=volume['Attachments'][0]['Device'],
                        InstanceId=volume['Attachments'][0]['InstanceId'])
        else:
            create_node(args[0], args[1], "Volumes", Name=name_tag, AvailabilityZone=volume['AvailabilityZone'],
                        Size=volume['Size'], VolumeId=volume['VolumeId'], VolumeType=volume['VolumeType'],
                        Encrypted=volume['Encrypted'])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_reservations(*args):
    reservations = args[2].describe_instances()
    if reservations['Reservations']:
        for reservation in reservations['Reservations']:
            create_ec2(args[0], args[1], reservation)


def create_ec2(*args):
    start_timer = time.time()
    for instance in args[2]['Instances']:
        if not instance['State']['Code'] == 48:
            name = find_tags(args[1], instance)
            network_interface_id = instance['NetworkInterfaces'][0]['NetworkInterfaceId']
            graph_ec2 = create_node(args[0], args[1], "EC2", InstanceId=instance['InstanceId'], Name=name,
                                    state=instance['State']['Name'], SubnetId=instance['SubnetId'],
                                    NetworkInterfaceId=network_interface_id, type=instance['InstanceType']
                                    )
            graph_subnet = find_node(args[0], args[1], label="Subnet", property_key='SubnetId',
                                     property_value=instance['SubnetId'])
            if graph_subnet is not None:
                create_relationship(args[0], args[1], graph_ec2, "ATTACHED", graph_subnet)
            graph_eip = find_node(args[0], args[1], label="EIP", property_key='NetworkInterfaceId',
                                  property_value=network_interface_id)
            if graph_eip is not None:
                create_relationship(args[0], args[1], graph_eip, "ASSOCIATION", graph_ec2)
            graph_volume = find_node(args[0], args[1], label="Volumes", property_key='InstanceId',
                                     property_value=instance['InstanceId'])
            if graph_volume is not None:
                create_relationship(args[0], args[1], graph_ec2, "ATTACHED", graph_volume)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_rds(*args):
    start_timer = time.time()
    rds = boto3.session.Session(profile_name=args[2]).client('rds', region_name=args[3])
    databases = rds.describe_db_instances()

    args[1].info("Found " + str(len(databases['DBInstances'])) + " RDS Instances")
    for db in databases['DBInstances']:
        graph_rds = create_node(args[0], args[1], "RDS", rdsId=db['DBInstanceIdentifier'], DBInstanceClass=db['DBInstanceClass'],
                    Engine=db['Engine'], EngineVersion=db['EngineVersion'], MultiAZ=db['MultiAZ'],
                    AllocatedStorage=db['AllocatedStorage'], Name=db['DBInstanceIdentifier'])
        for subnetId in db['DBSubnetGroup']['Subnets']:
            graph_subnet = find_node(args[0], args[1], label="Subnet", property_key='SubnetId', property_value=subnetId['SubnetIdentifier'])
            if graph_subnet is not None:
                create_relationship(args[0], args[1], graph_rds, "BELONGS", graph_subnet)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_elc(*args):
    start_timer = time.time()
    elasticache = boto3.session.Session(profile_name=args[2]).client('elasticache', region_name=args[3])
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    args[1].info("Found " + str(len(elcs)) + " ElastiCache Clusters")
    for elc in elcs:
        create_node(args[0], args[1], "ElastiCache", elcId=elc['CacheClusterId'])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_eks(*args):
    start_timer = time.time()
    eks = boto3.session.Session(profile_name=args[2]).client('eks', region_name=args[3])
    try:
        list_clusters = eks.list_clusters()
        args[1].info("Found " + str(len(list_clusters['clusters'])) + " EKS Clusters")
        for node in list_clusters['clusters']:
            describe_cluster = eks.describe_cluster(name=node)
            list_nodegroups = eks.list_nodegroups(clusterName=node)
            try:
                list_fargate_profiles = eks.list_fargate_profiles(clusterName=node)
            except eks.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    args[1].error("eks.list_fargate_profiles: " + e.response['Error']['Message'])
                else:
                    args[1].error("Unexpected error: %s" % e)
            describe_cluster = describe_cluster['cluster']
            resourcesVpcConfig = describe_cluster['resourcesVpcConfig']
            graph_eks = create_node(args[0], args[1], "EKS",
                                    Name=describe_cluster['name'],
                                    platformVersion=describe_cluster['platformVersion'],
                                    status=describe_cluster['status'],
                                    version=describe_cluster['version'],
                                    subnetIds=resourcesVpcConfig['subnetIds'],
                                    securityGroupIds=resourcesVpcConfig['securityGroupIds'],
                                    vpcId=resourcesVpcConfig['vpcId'],
                                    endpointPublicAccess=resourcesVpcConfig['endpointPublicAccess'],
                                    endpointPrivateAccess=resourcesVpcConfig['endpointPrivateAccess'],
                                    )
            for subnetId in resourcesVpcConfig['subnetIds']:
                graph_subnet = find_node(args[0], args[1], label="Subnet", property_key='SubnetId',
                                         property_value=subnetId)
                if graph_subnet is not None:
                    create_relationship(args[0], args[1], graph_eks, "BELONGS", graph_subnet)

    except eks.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            args[1].error("eks.list_clusters: " + e.args[0])
        else:
            args[1].error("Unexpected error: %s" % e)

    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_elb(*args):
    start_timer = time.time()
    loadbalancer = boto3.session.Session(profile_name=args[2]).client('elb', region_name=args[3])
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    args[1].info("Found " + str(len(elbs)) + " ELBs")
    for elb in elbs:
        graph_elb = create_node(args[0], args[1], "ELB", Name=elb['LoadBalancerName'],
                                CanonicalHostedZoneName=elb['CanonicalHostedZoneName'])
        for subnet in elb['Subnets']:
            graph_subnet = find_node(args[0], args[1], label="Subnet", property_key='SubnetId', property_value=subnet)
            if graph_subnet is not None:
                create_relationship(args[0], args[1], graph_elb, "BELONGS", graph_subnet)
        for instance in elb["Instances"]:
            graph_instance = find_node(args[0], args[1], label="EC2", property_key='InstanceId',
                                       property_value=instance['InstanceId'])
            if graph_instance is not None:
                create_relationship(args[0], args[1], graph_instance, "BELONGS", graph_elb)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_eip(*args):
    start_timer = time.time()
    eips = args[2].describe_addresses()
    args[1].info("Found " + str(len(eips)) + " EIPs")
    for eip in eips['Addresses']:
        network_interface_id = check_key(eip, 'NetworkInterfaceId')
        create_node(args[0], args[1], "EIP", AllocationId=eip['AllocationId'], PublicIp=eip['PublicIp'],
                    Domain=eip['Domain'], PublicIpv4Pool=eip['PublicIpv4Pool'], Name=eip['PublicIp'],
                    AssociationId=check_key(eip, 'AssociationId'), NetworkInterfaceId=network_interface_id
                    )
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_network_interfaces(*args):
    start_timer = time.time()
    interfaces = args[2].describe_network_interfaces()
    args[1].info("Found " + str(len(interfaces['NetworkInterfaces'])) + " Interfaces")
    for interface in interfaces['NetworkInterfaces']:
        create_node(args[0], args[1], "Interfaces", Description=interface['Description'],
                    RequesterId=check_key(interface, 'RequesterId'), NetworkInterfaceId=interface['NetworkInterfaceId'])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_topics(*args):
    start_timer = time.time()
    topics = args[2].list_topics()
    args[1].info("Found " + str(len(topics['Topics']))  + " Topics")
    for topic in topics['Topics']:
        topic_attributes = args[2].get_topic_attributes(TopicArn=topic['TopicArn'])
        create_node(args[0], args[1], "Topic", Name=topic_attributes['Attributes']['DisplayName'],
                    TopicArn=topic_attributes['Attributes']['TopicArn'],
                    Owner=topic_attributes['Attributes']['Owner'],
                    EffectiveDeliveryPolicy=topic_attributes['Attributes']['EffectiveDeliveryPolicy'],
                    SubscriptionsPending=topic_attributes['Attributes']['SubscriptionsPending'],
                    SubscriptionsConfirmed=topic_attributes['Attributes']['SubscriptionsConfirmed']
                    )
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_sns(*args):
    start_timer = time.time()
    sns = boto3.session.Session(profile_name=args[2]).client('sns', region_name=args[3])
    create_topics(args[0], args[1], sns)
    subscriptions = sns.list_subscriptions()
    args[1].info("Found " + str(len(subscriptions['Subscriptions']))  + " Subscriptions")
    for subscription in subscriptions['Subscriptions']:
        graph_subscription = create_node(args[0], args[1], "SNS_Subscriptions",
                                         Name=subscription['SubscriptionArn'],
                                         SubscriptionArn=subscription['SubscriptionArn'],
                                         Owner=subscription['Owner'],
                                         Protocol=subscription['Protocol'],
                                         Endpoint=subscription['Endpoint'],
                                         TopicArn=subscription['TopicArn']
                                         )
        graph_topic = find_node(args[0], args[1], label="Topic", property_key='TopicArn',
                                property_value=subscription['TopicArn'])
        if graph_topic is not None:
            create_relationship(args[0], args[1], graph_subscription, "SUBSCRIBED", graph_topic)

    try:
        platform_applications = sns.list_platform_applications()
        args[1].info("Found " + str(len(platform_applications['PlatformApplications'])) + " PlatformApplications")
        for application in platform_applications['PlatformApplications']:
            create_node(args[0], args[1], "PlatformApplications",
                        PlatformApplicationArn=application['PlatformApplicationArn'],
                        Attributes=application['Attributes']
                        )
    except sns.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidAction':
            args[1].error("sns.list_platform_applications: " + e.response['Error']['Message'])
        else:
            args[1].error("Unexpected error: %s" % e)

    try:
        phone_numbers_opted_out = sns.list_phone_numbers_opted_out()
    except (sns.exceptions.ClientError, sns.exceptions.AuthorizationErrorException) as e:
        if e.response['Error']['Code'] == 'AuthorizationError':
            args[1].error("sns.list_phone_numbers_opted_out: " + e.response['Error']['Message'])
        elif e.response['Error']['Code'] == 'InvalidAction':
            args[1].error("sns.list_phone_numbers_opted_out: " + e.response['Error']['Message'])
        else:
            args[1].error("Unexpected error: %s" % e)
    # tags_for_resource = sns.list_tags_for_resource()
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_target_groups(*args):
    start_timer = time.time()
    tgs = args[2].describe_target_groups(LoadBalancerArn=args[3])['TargetGroups']
    args[1].info("Found " + str(len(tgs)) + " TargetGroups")
    for tg in tgs:
        tg_arn = tg['TargetGroupArn']
        targets = args[2].describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
        graph_tg = create_node(args[0], args[1], "Target Group", Name=tg['TargetGroupName'])
        create_relationship(args[0], args[1], graph_tg, "ATTACHED", args[4])

        args[1].info("Found " + str(len(targets)) + " Targets")
        for target in targets:
            graph_instance = find_node(args[0], args[1], label="EC2", property_key='instanceId',
                                       property_value=target['Target']['Id'])
            if graph_instance is not None:
                create_relationship(args[0], args[1], graph_instance, "ATTACHED", graph_tg)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_asg(*args):
    start_timer = time.time()
    autoscaling = boto3.session.Session(profile_name=args[2]).client('autoscaling', region_name=args[3])
    asgs = autoscaling.describe_auto_scaling_groups()['AutoScalingGroups']
    args[1].info("Found " + str(len(asgs)) + " ASGs")
    for asg in asgs:
        graph_asg = create_node(args[0], args[1], "ASG",
                                Name=asg['AutoScalingGroupName'],
                                LaunchConfigurationName=asg['LaunchConfigurationName'],
                                MinSize=asg['MinSize'],
                                MaxSize=asg['MaxSize'],
                                DesiredCapacity=asg['DesiredCapacity'])

        graph_subnet = find_node(args[0], args[1], label="Subnet", property_key='SubnetId',
                                 property_value=asg['VPCZoneIdentifier'])
        if graph_subnet is not None:
            create_relationship(args[0], args[1], graph_asg, "ATTACHED", graph_subnet)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_alb(*args):
    start_timer = time.time()
    elbv2 = boto3.session.Session(profile_name=args[2]).client('elbv2', region_name=args[3])
    albs = elbv2.describe_load_balancers()['LoadBalancers']
    args[1].info("Found " + str(len(albs)) + " ALBs")
    for alb in albs:
        graph_alb = create_node(args[0], args[1], "ALB", Name=alb['LoadBalancerName'], dnsname=alb['DNSName'],
                                scheme=alb['Scheme'], VpcId=alb['VpcId'])
        alb_arn = alb['LoadBalancerArn']

        for azs in alb['AvailabilityZones']:
            graph_subnet = find_node(args[0], args[1], label="Subnet", property_key='SubnetId',
                                     property_value=azs['SubnetId'])
            if graph_subnet is not None:
                create_relationship(args[0], args[1], graph_alb, "ATTACHED", graph_subnet)
        create_target_groups(args[0], args[1], elbv2, alb_arn, graph_alb)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_lambda(*args):
    start_timer = time.time()
    lambdaFunctions = boto3.session.Session(profile_name=args[2]).client('lambda', region_name=args[3])
    lambdas = lambdaFunctions.list_functions()['Functions']
    args[1].info("Found " + str(len(lambdas)) + " Lambdas")
    for l in lambdas:
        create_node(args[0], args[1], "Lambda", Name=l['FunctionName'])
    global has_lambda
    has_lambda = False
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_sg(*args):
    start_timer = time.time()
    security_groups = args[2].describe_security_groups()
    args[1].info("Found " + str(len(security_groups['SecurityGroups'])) + " SecurityGroups")
    for sg in security_groups['SecurityGroups']:
        graph_sg = create_node(args[0], args[1], "SecurityGroup", securityGroupId=sg['GroupId'], Name=sg['GroupName'],
                               VpcId=sg['VpcId'])
        graph_vpc = find_node(args[0], args[1], label="Subnet", property_key='VpcId', property_value=sg['VpcId'])
        if graph_vpc is not None:
            create_relationship(args[0], args[1], graph_sg, "BELONGS", graph_vpc)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_dynamodb(*args):
    start_timer = time.time()
    dynamodb = boto3.session.Session(profile_name=args[2]).client('dynamodb', region_name=args[3])
    dynamo_tables = dynamodb.list_tables()['TableNames']
    args[1].info("Found " + str(len(dynamo_tables)) + " DynamoDB Tables")
    for table_name in dynamo_tables:
        table_info = dynamodb.describe_table(TableName=table_name)['Table']
        create_node(args[0], args[1], "DynamoDB", Name=table_name,
                    write_capacity=table_info['ProvisionedThroughput']['WriteCapacityUnits'],
                    read_capacity=table_info['ProvisionedThroughput']['ReadCapacityUnits'])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_instance_relationships(*args):
    start_timer = time.time()
    args[1].info("Creating security-group - user-group relationships")
    instances = args[2].describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [args[4]['GroupId']]}])
    if instances['Reservations']:
        for instance in instances['Reservations']:
            instance_id = instance['Instances'][0]['InstanceId']
            graph_ec2 = find_node(args[0], args[1], label="EC2", property_key='instanceId', property_value=instance_id)
            if graph_ec2 is not None:
                args[1].info("Creating EC2 Instance Relationship for: " + graph_ec2['Name'])
                create_relationship(args[0], args[1], graph_ec2, "ATTACHED", args[3])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_database_sg_relationships(*args):
    start_timer = time.time()
    args[1].info("Creating security-group - database relationships")
    rds = boto3.session.Session(profile_name=args[2]).client('rds', region_name=args[3])
    databases = rds.describe_db_instances()['DBInstances']
    for db in databases:
        db_sgs = db['VpcSecurityGroups']
        for db_sg in db_sgs:
            if db_sg['VpcSecurityGroupId'] == args[5]['GroupId']:
                graph_rds = find_node(args[0], args[1], label="RDS", property_key='rdsId',
                                      property_value=db['DBInstanceIdentifier'])
                if graph_rds is not None:
                    create_relationship(args[0], args[1], graph_rds, "ATTACHED", args[4])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_database_subnet_relationships(*args):
    start_timer = time.time()
    databases = args[2].describe_db_instances()['DBInstances']
    for db_subnets in databases['DBSubnetGroup']['Subnets']:
        graph_rds = find_node(args[0], args[1], label="Subnets", property_key='SubnetId',
                              property_value=args[4]['SubnetIdentifier'])
        if graph_rds is not None:
            create_relationship(args[0], args[1], graph_rds, "ATTACHED", args[3])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_elasticache_relationships(*args):
    start_timer = time.time()
    args[1].info("Creating security-group - elasticache relationships")
    elasticache = boto3.session.Session(profile_name=args[2]).client('elasticache', region_name=args[3])
    elcs = elasticache.describe_cache_clusters()['CacheClusters']
    for elc in elcs:
        elc_sgs = elc['SecurityGroups']
        for elc_sg in elc_sgs:
            if elc_sg['SecurityGroupId'] == args[5]['GroupId']:
                graph_elc = find_node(args[0], args[1], label="ElastiCache", property_key='elcId',
                                      property_value=elc['CacheClusterId'])
                if graph_elc is not None:
                    create_relationship(args[0], args[1], graph_elc, "ATTACHED", args[4])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_elb_relationships(*args):
    start_timer = time.time()
    args[1].info("Creating security-group - elb relationships")
    loadbalancer = boto3.Session(profile_name=args[2]).client('elb', region_name=args[3])
    elbs = loadbalancer.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        elb_sgs = elb['SecurityGroups']
        for elb_sg in elb_sgs:
            if elb_sg == args[4]['GroupId']:
                graph_elb = find_node(args[0], args[1], label="ELB", property_key='name',
                                      property_value=elb['LoadBalancerName'])
                if graph_elb is not None:
                    create_relationship(args[0], args[1], graph_elb, "ATTACHED", args[3])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_lamda_relationships(*args):
    start_timer = time.time()
    args[1].info("Creating security-group - lambda relationships")
    lambda_functions = boto3.session.Session(profile_name=args[2]).client('lambda', region_name=args[3])
    lambdas = lambda_functions.list_functions()['Functions']
    for l in lambdas:
        if l.__contains__('VpcConfig') and l['VpcConfig'] != []:
            for lambda_sg in l['VpcConfig']['SecurityGroupIds']:
                if lambda_sg == args[4]['GroupId']:
                    graph_lambda = find_node(args[0], args[1], label="Lambda", property_key='name',
                                             property_value=l['FunctionName'])
                    create_relationship(args[0], args[1], graph_lambda, "ATTACHED", args[3])
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_useridgrouppairs_relationships(*args):
    start_timer = time.time()
    args[1].info("Creating security-group - user-group relationships")
    for group in args[2]['UserIdGroupPairs']:
        graph_from_sg = find_node(args[0], args[1], label="SecurityGroup", property_key='securityGroupId',
                                  property_value=group['GroupId'])
        if graph_from_sg is not None:
            if args[2]['IpProtocol'] == '-1':
                protocol = 'All'
                port_range = '0 - 65535'
            else:
                protocol = args[2]['IpProtocol']
                if args[2]['FromPort'] == args[2]['ToPort']:
                    port_range = args[2]['FromPort']
                else:
                    port_range = "%d - %d" % (args[2]['FromPort'], args[2]['ToPort'])
            create_relationship(args[0], args[1], graph_from_sg, "ATTACHED", args[3], protocol=protocol,
                                port=port_range)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_ipranges_relationships(*args):
    start_timer = time.time()
    args[1].info("Creating security-group - ip range relationships")
    for cidr in args[2]['IpRanges']:
        try:
            graph_cidr = find_node(args[0], args[1], label="IP", property_key='cidr', property_value=cidr['CidrIp'])
        except:
            graph_cidr = create_node(args[0], args[1], "IP", cidr=cidr['CidrIp'])
        if args[2]['IpProtocol'] == '-1':
            protocol = 'All'
            port_range = '0 - 65535'
        else:
            protocol = args[2]['IpProtocol']
            if args[2]['FromPort'] == args[2]['ToPort']:
                port_range = args[2]['FromPort']
            else:
                port_range = "%d - %d" % (args[2]['FromPort'], args[2]['ToPort'])
        if graph_cidr is not None:
            create_relationship(args[0], args[1], graph_cidr, "ATTACHED", args[3], protocol=protocol, port=port_range)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def create_sg_relationships(*args):
    start_timer = time.time()
    security_groups = args[4].describe_security_groups()
    args[1].info("Creating security-group relationships")
    for sg in security_groups['SecurityGroups']:
        graph_sg = find_node(args[0], args[1], label="SecurityGroup", property_key='securityGroupId',
                             property_value=sg['GroupId'])
        if graph_sg is not None:
            ingress_rules = sg['IpPermissions']
            for rule in ingress_rules:
                if rule['UserIdGroupPairs']:
                    create_useridgrouppairs_relationships(args[0], args[1], rule, graph_sg)
                elif rule['IpRanges']:
                    create_ipranges_relationships(args[0], args[1], rule, graph_sg)

        create_instance_relationships(args[0], args[1], args[4], graph_sg, sg)
        create_database_sg_relationships(args[0], args[1], args[2], args[3], graph_sg, sg)
        create_elasticache_relationships(args[0], args[1], args[2], args[3], graph_sg, sg)
        create_elb_relationships(args[0], args[1], args[2], args[3], graph_sg, sg)
        if args[5]:
            create_lamda_relationships(args[0], args[1], args[2], args[3], graph_sg, sg)
    args[1].debug("Module Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


def initialise_logger():
    start_timer = time.time()
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    # create a file & console handlers
    ch = logging.StreamHandler()
    fh = logging.FileHandler('./info.log')
    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.info("********************************")
    logger.info("Initialising AWS Topology Mapper")
    logger.info("********************************")
    return { 'log_handle': logger, 'console_handle': ch}


def main():
    start_timer = time.time()
    logger_dict = initialise_logger()
    logger = logger_dict['log_handle']
    ch = logger_dict['console_handle']
    graph = Graph(user="neo4j", password="letmein", host="localhost")

    graph.delete_all()
    has_lambda = True
    aws_profiles = ["easyjet-prod", "easyjet-nonprod"]
    aws_profiles = ["blue-badge"]

    for profile in aws_profiles:
        logger_dict['log_handle'].info("Specifying aws profile: " + profile)
        formatter = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - ' + profile + ' - %(message)s')
        ch.setFormatter(formatter)
        sts = boto3.session.Session(profile_name=profile).client('sts')

        logger_dict['log_handle'].info("Query AWS Account")
        caller_identify = sts.get_caller_identity()
        logger_dict['log_handle'].info("Executing as AWS User: " + caller_identify['Arn'])
        logger_dict['log_handle'].info("Define AWS Provider as account: " + caller_identify['Account'])
        graph_provider = create_node(graph, logger, "Provider", Name='AWS', Account=caller_identify['Account'])

        ec2 = boto3.session.Session(profile_name=profile).client('ec2')
        describe_regions = ec2.describe_regions()

        for describe_region in describe_regions['Regions']:
            region = describe_region['RegionName']
            logger.info("Querying region: " + region)
            formatter = logging.Formatter(
                '%(asctime)s - %(funcName)s - %(levelname)s - ' + profile + '_' + region + ' - %(message)s')
            ch.setFormatter(formatter)
            logger.info("Defining client sessions")
            logger.info("Creating Graph Node for Region: "+ region)

            graph_region = create_node(graph, logger, "Region", Name=region)
            create_relationship(graph, logger, graph_region, "BELONGS", graph_provider)

            ec2 = boto3.session.Session(profile_name=profile).client('ec2', region_name=region)
            create_eip(graph, logger, ec2)
            create_vpc(graph, logger, graph_region, ec2)
            create_sg(graph, logger, ec2)
            create_ec2_volumes(graph, logger, ec2)
            create_reservations(graph, logger, ec2)
            create_sns(graph, logger, profile, region)
            create_eks(graph, logger, profile, region)
            create_rds(graph, logger, profile, region)
            create_elb(graph, logger, profile, region)
            create_asg(graph, logger, profile, region)
            create_alb(graph, logger, profile, region)
            create_elc(graph, logger, profile, region)
            if has_lambda:
                create_lambda(graph, logger, profile, region)
                create_dynamodb(graph, logger, profile, region)
            create_sg_relationships(graph, logger, profile, region, ec2, has_lambda)
    logger.info("Audit Completed in " + str(convert_time(time.time() - start_timer)) + " seconds")


if __name__ == '__main__':
    start_time = time.time()
    main()
