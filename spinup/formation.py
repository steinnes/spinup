from collections import defaultdict
from copy import deepcopy
import time

from troposphere import (
    Base64,
    FindInMap,
    GetAZs,
    GetAtt,
    Join,
    Output,
    Parameter,
    Ref,
    Select,
    Sub,
    Tags,
    Template,
)

from troposphere import autoscaling, eks, elasticache, elasticsearch, iam, rds

from troposphere.ec2 import (
    InternetGateway,
    NetworkAcl,
    NetworkAclEntry,
    Route,
    RouteTable,
    SecurityGroup,
    SecurityGroupEgress,
    SecurityGroupIngress,
    Subnet,
    SubnetNetworkAclAssociation,
    SubnetRouteTableAssociation,
    VPC,
    VPCGatewayAttachment,
)

from troposphere.iam import InstanceProfile, Role


class ASGTags(autoscaling.Tags):
    """ Our own implementation of ASGTags which circumvents a constructor which only takes
    kwargs, so tag-keys must be strings.  Where as we need them to by dynamic in the case
    of our k8s worker nodes, since the 'kubernetes.io/cluster/{clusterId}' embeds the name
    (or id) of the cluster in the key, so in troposphere it must be:
    Tags({Sub('kubernetes.io/cluster/{clusterId}', clusterId=Ref(self.eks_cluster)): 'owned'})

    """
    def __init__(self, tags=None):
        super(ASGTags, self).__init__()
        if tags is not None:
            if isinstance(tags, Tags):
                tags = tags.tags
            if isinstance(tags, dict):
                tags = [{'Key': key, 'Value': value} for key, value in tags.items()]
            if isinstance(tags, list):
                for tag in tags:
                    t = deepcopy(tag)
                    if 'PropagateAtLaunch' not in t:
                        t['PropagateAtLaunch'] = str(self.defaultPropagateAtLaunch).lower()
                    self.tags.append(t)
            else:
                raise TypeError('{} is an invalid type for {}'.format(
                    type(tags).__name__, type(self).__name__
                ))


class Formation:
    VPC_CONFIG = {
        'cidr': '10.0.0.0/16',
        'subnets': [
            '10.0.0.0/19',
            '10.0.32.0/19',
            '10.0.64.0/19',
        ]
    }

    def __init__(self, basename=None, options=None):
        self.t = Template()
        self.tags = Tags()
        if basename is None:
            basename = 'spinup'
        self.basename = basename
        opts = defaultdict(bool)
        opts['vpc'] = True
        opts['eks'] = True

        if options is not None:
            opts.update(options)

        if opts['vpc']:
            self.create_vpc()
        if opts['eks']:
            self.create_eks()
            self.create_eks_workers()
        if opts['postgres']:
            self.create_postgres()
        if opts['redis']:
            self.create_redis()
        if opts['elasticsearch']:
            self.create_elasticsearch()

    def serial_name(self, name):
        if not hasattr(self, '_series') or getattr(self, '_series') is None:
            self._series = defaultdict(int)
        counter = self._series[name]
        self._series[name] += 1
        return "{}{}".format(name, counter)

    def json(self):
        return self.t.to_json()

    def gress(self, cls, name, src, dst, port, proto, description, deps=None):
        kwargs = dict(
            Description=description,
        )
        if proto is None:
            proto = "tcp"

        if port is not None:
            try:
                from_port = port[0]
                to_port = port[1]
            except TypeError:
                from_port, to_port = int(port), int(port)
            finally:
                kwargs['FromPort'] = from_port
                kwargs['ToPort'] = to_port

        kwargs['IpProtocol'] = proto

        if deps is not None:
            kwargs['DependsOn'] = deps

        return self.t.add_resource(cls(name, **kwargs))

    def ingress(self, src, dst, port=None, proto=None, description=None, deps=None):
        name = self.serial_name("{}Ingress".format(dst.name))
        if description is None:
            description = 'Allow {dst} to to connect to {src}:{port}'.format(src=src.name, dst=dst.name, port=port if port is not None else 'all')
        return self.gress(
            lambda *args, **kw: SecurityGroupIngress(*args, SourceSecurityGroupId=Ref(src), GroupId=Ref(dst), **kw),
            name=name, src=src, dst=dst, port=port, proto=proto, description=description, deps=deps
        )

    def egress(self, src, dst, port=None, proto=None, description=None, deps=None):
        name = self.serial_name("{}Egress".format(dst.name))
        if port is None:
            port = (0, 65535)
        if description is None:
            description = 'Allow {src} to to connect to {dst}:{port}'.format(src=src.name, dst=dst.name, port=port if port is not None else 'all')
        return self.gress(
            lambda *args, **kw: SecurityGroupEgress(*args, DestinationSecurityGroupId=Ref(dst), GroupId=Ref(src), **kw),
            name=name, src=src, dst=dst, port=port, proto=proto, description=description, deps=deps
        )

    def create_vpc(self):
        t = self.t
        self.vpc = t.add_resource(VPC(
            "{}Vpc".format(self.basename),
            CidrBlock=self.VPC_CONFIG['cidr'],
            InstanceTenancy='default',
            Tags=self.tags
        ))

        self.igw = t.add_resource(InternetGateway(
            "{}InternetGateway".format(self.basename),
        ))
        self.igw_attachment = t.add_resource(VPCGatewayAttachment(
            "{}IGWAttachment".format(self.basename),
            VpcId=Ref(self.vpc),
            InternetGatewayId=Ref(self.igw),
        ))

        self.route_table = t.add_resource(RouteTable(
            'RouteTable',
            VpcId=Ref(self.vpc),
            Tags=self.tags
        ))
        t.add_resource(Route(
            '{}DefaultInternetRoute'.format(self.basename),
            DependsOn=self.igw_attachment.name,
            GatewayId=Ref(self.igw),
            DestinationCidrBlock='0.0.0.0/0',
            RouteTableId=Ref(self.route_table)
        ))

        self.network_acl = t.add_resource(NetworkAcl(
            '{}NetworkAcl'.format(self.basename),
            VpcId=Ref(self.vpc),
            Tags=self.tags + Tags(Name='{}NetworkAcl'.format(self.basename))
        ))

        # Create two ACL entries, one inbound, one outbound, allowing everything
        for egress in ('true', 'false'):
            t.add_resource(
                NetworkAclEntry(
                    'AllowEverythingInternally{}'.format('Out' if egress == 'true' else 'In'),  # noqa
                    NetworkAclId=Ref(self.network_acl),
                    CidrBlock='0.0.0.0/0',
                    RuleNumber='100',
                    Protocol='-1',
                    RuleAction='allow',
                    Egress=egress,
                )
            )

        self.subnets = []
        for zone, block in enumerate(self.VPC_CONFIG['subnets']):
            name = '{}Subnet{}'.format(self.basename, zone)
            subnet = t.add_resource(
                Subnet(
                    name,
                    AvailabilityZone=Select(zone, GetAZs(Ref('AWS::Region'))),
                    CidrBlock=block,
                    Tags=self.tags + Tags(Name=name),
                    VpcId=Ref(self.vpc),
                )
            )
            self.subnets.append(subnet)
            t.add_resource(
                SubnetRouteTableAssociation(
                    '{}Routes'.format(name),
                    SubnetId=Ref(subnet),
                    RouteTableId=Ref(self.route_table),
                )
            )
            t.add_resource(
                SubnetNetworkAclAssociation(
                    '{}Acl'.format(name),
                    SubnetId=Ref(subnet),
                    NetworkAclId=Ref(self.network_acl),
                )
            )

    def create_eks(self):
        """ Create an EKS cluster inside the given VPC """
        eks_role_name = "eksClusterManager"
        # 1. Create IAM Role(s)
        eks_role = self.t.add_resource(iam.Role(
            eks_role_name,
            AssumeRolePolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "eks.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            ManagedPolicyArns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy", "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"],  # noqa
        ))
        # 2. Create Security Group for EKS Cluster Control Plane
        eks_cluster_control_sg = self.t.add_resource(SecurityGroup(
            "{}EKSClusterControlPlaneSG".format(self.basename),
            GroupDescription="Security group for the {} EKS Control Plane".format(self.basename),
            VpcId=Ref(self.vpc)
        ))

        # 3. Create EKS Cluster
        self.eks_cluster = self.t.add_resource(eks.Cluster(
            self.basename,
            RoleArn=GetAtt(eks_role, "Arn"),
            ResourcesVpcConfig=eks.ResourcesVpcConfig(
                SecurityGroupIds=[Ref(eks_cluster_control_sg)],
                SubnetIds=[Ref(subnet) for subnet in self.subnets]
            )
        ))
        self.eks_cluster_sg = eks_cluster_control_sg

        # 4. Add outputs required to update ~/.kube/config
        self.t.add_output(Output(
            "EKSClusterEndpoint",
            Description="EKS Cluster API endpoint for kubectl",
            Value=GetAtt(self.eks_cluster, "Endpoint"),
        ))
        self.t.add_output(Output(
            "EKSClusterCertificateAuthorityData",
            Description="EKS Cluster CA data for kubectl",
            Value=GetAtt(self.eks_cluster, "CertificateAuthorityData"),
        ))
        self.t.add_output(Output(
            "EKSClusterArn",
            Description="EKS Cluster ARN",
            Value=GetAtt(self.eks_cluster, "Arn")
        ))

    def create_eks_workers(self):
        """ Create the EKS worker nodes for the current EKS cluster in the current VPC

        This is based on the yaml found here:
         https://amazon-eks.s3-us-west-2.amazonaws.com/cloudformation/2018-08-30/amazon-eks-nodegroup.yaml

        """
        node_instance_type = self.t.add_parameter(Parameter(
            "EKSNodeInstanceType",
            Default="m5.large",
            Description="Choose EKS worker node instance type",
            Type="String",
            AllowedValues=[
                "t2.micro",
                "t2.small",
                "m3.medium",
                "t2.medium",
                "m5.large",
                "m5.xlarge",
                "c5.large",
                "c5.xlarge"
            ],
        ))

        node_count = self.t.add_parameter(Parameter(
            "EKSNodeCount",
            Default="3",
            Description="Number of EKS worker nodes",
            Type="Number",
        ))

        # non-GPU enabled AMI's, from: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
        self.t.add_mapping("AMIForRegion", {
            'eu-west-1': {'ami': 'ami-0c7a4976cb6fafd3a'},
            'us-east-1': {'ami': 'ami-0440e4f6b9713faf6'},
            'us-west-2': {'ami': 'ami-0a54c984b9f908c81'},
        })

        eks_node_instance_role = self.t.add_resource(Role(
            "eksNodeInstanceRole",
            Path="/",
            ManagedPolicyArns=[
                "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
                "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
            ],
            AssumeRolePolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": ["sts:AssumeRole"],
                        "Effect": "Allow",
                        "Principal": {
                            "Service": ["ec2.amazonaws.com"]
                        }
                    }
                ]
            },
            Policies=[
                iam.Policy(
                    PolicyName="k8snoderoute53zone",
                    PolicyDocument={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "route53:ChangeResourceRecordSets"
                                ],
                                "Resource": [
                                    "arn:aws:route53:::hostedzone/*"
                                ]
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "route53:ListHostedZones",
                                    "route53:ListResourceRecordSets"
                                ],
                                "Resource": [
                                    "*"
                                ]
                            }
                        ]
                    }
                )
            ],
        ))
        self.t.add_output(Output(
            "eksNodeInstanceRoleArn",
            Description="Role created for the EKS nodes in this stack/cluster",
            Value=GetAtt(eks_node_instance_role, "Arn")
        ))
        eks_node_instance_profile = self.t.add_resource(InstanceProfile(
            "eksNodeInstanceProfile",
            Path="/",
            Roles=[Ref(eks_node_instance_role)],
        ))

        self.eks_node_sg = self.t.add_resource(SecurityGroup(
            "eksNodeSecurityGroup",
            VpcId=Ref(self.vpc),
            GroupDescription="Security group for all nodes in the cluster",
            Tags=self.tags + Tags({"kubernetes.io/cluster/{}".format(self.basename): "owned"}),
        ))
        # allow all traffic between EKS cluster and EKS nodes
        self.ingress(self.eks_cluster_sg, self.eks_node_sg, proto="-1", deps=self.eks_node_sg.name)
        self.egress(self.eks_cluster_sg, self.eks_node_sg, proto="-1", deps=self.eks_node_sg.name)
        self.ingress(self.eks_node_sg, self.eks_cluster_sg, proto="-1", deps=self.eks_node_sg.name)

        self.ingress(self.eks_node_sg, self.eks_node_sg, proto="-1", deps=self.eks_node_sg.name,
                description="Allow nodes to communicate with each other")

        self.eks_node_ssh_key_name = self.t.add_parameter(Parameter(
            "SSHKeyName",
            Type="AWS::EC2::KeyPair::KeyName",
            Description="The EC2 Key Pair to allow SSH access to the instances",
        ))
        self.eks_node_launch_config = self.t.add_resource(autoscaling.LaunchConfiguration(
            "NodeLaunchConfig",
            UserData=Base64(Join("",
                ["#!/bin/bash -xe\n",
                 "set -o xtrace\n",
                 "/etc/eks/bootstrap.sh ", Ref(self.eks_cluster), "\n",
                 "/opt/aws/bin/cfn-signal --exit-code $?",
                 "       --stack ", Ref("AWS::StackName"),
                 "       --resource eksNodeGroup",
                 "       --region ", Ref("AWS::Region"), "\n"]
            )),
            ImageId=FindInMap("AMIForRegion", Ref("AWS::Region"), "ami"),
            KeyName=Ref(self.eks_node_ssh_key_name),
            SecurityGroups=[Ref(self.eks_node_sg)],
            IamInstanceProfile=Ref(eks_node_instance_profile),
            InstanceType=Ref(node_instance_type),
            AssociatePublicIpAddress="true",
            DependsOn=self.eks_cluster.name,
        ))
        # Warning: this 'kubernetes.io/cluster/{clustername}' tag is crucial for the nodes to
        # be willing to join their cluster.  If this value is wrong, it will fail to register
        # but still run all kinds of periodical checks and interface with the master server(s)
        # while generating all kinds of errors which will only send you down various rabbit holes.
        combined_tags = ASGTags(self.tags) + ASGTags({
            Sub("kubernetes.io/cluster/${ClusterName}", ClusterName=Ref(self.eks_cluster)): 'owned',
            'Name': Sub('${AWS::StackName}-eks-worker-node'),
        })

        self.eks_node_asg = self.t.add_resource(autoscaling.AutoScalingGroup(
            "eksNodeGroup",
            DesiredCapacity=Ref(node_count),
            Tags=combined_tags,
            MinSize=Ref(node_count),
            MaxSize=Ref(node_count),
            VPCZoneIdentifier=[Ref(subnet) for subnet in self.subnets],
            LaunchConfigurationName=Ref(self.eks_node_launch_config),
        ))

    def create_postgres(self):
        db_sg = self.t.add_resource(SecurityGroup(
            "{}RDSSecurityGroup".format(self.basename),
            GroupDescription="Security group for {} RDS".format(self.basename),
            VpcId=Ref(self.vpc)
        ))

        self.ingress(self.eks_node_sg, db_sg, port=5432, deps=self.eks_node_sg.name,
            description="Allow k8s nodes (and pods) to connect to RDS")

        db_subnet_groups = self.t.add_resource(rds.DBSubnetGroup(
            "{}DBSubnetGroup".format(self.basename),
            DBSubnetGroupDescription="Subnets available for RDS DB instances",
            SubnetIds=[Ref(subnet) for subnet in self.subnets]
        ))

        dbclass = self.t.add_parameter(Parameter(
            "DBNodeType",
            Default="db.t2.small",
            Description="Database instance class",
            Type="String",
            AllowedValues=["db.t2.micro", "db.t2.small", "db.t2.medium",
                           "db.m4.large", "db.m4.xlarge", "db.m4.2xlarge"],
            ConstraintDescription="must select a valid database instance type.",
        ))
        dballocatedstorage = self.t.add_parameter(Parameter(
            "DBDiskSize",
            Default="50",
            Description="The size of the database (Gb)",
            Type="Number",
            MinValue="5",
            MaxValue="1024",
            ConstraintDescription="must be between 5 and 1024Gb.",
        ))

        db_username = self.t.add_parameter(Parameter(
            "DBMasterUsername",
            Description="The master username for the RDS database",
            Type="String",
        ))

        db_password = self.t.add_parameter(Parameter(
            "DBMasterUserPassword",
            Default="super-secret-password-please-change",
            Description="The master user password for the RDS database",
            Type="String",
        ))

        self.db = self.t.add_resource(rds.DBInstance(
            "{}postgres".format(self.basename),
            AllocatedStorage=Ref(dballocatedstorage),
            DBInstanceClass=Ref(dbclass),
            DBName="db",
            DBParameterGroupName='postgresql-production-9-6',
            DBSubnetGroupName=Ref(db_subnet_groups),
            Engine="postgres",
            EngineVersion="9.6",
            MasterUserPassword=Ref(db_password),
            MasterUsername=Ref(db_username),
            VPCSecurityGroups=[Ref(db_sg)],
        ))
        self.t.add_output(Output(
            "SqlalchemyDatabaseUri",
            Description="RDS Database URI",
            Value=Join("", [
                "postgres://",
                Ref(db_username),
                ":",
                Ref(db_password),
                "@",
                GetAtt(self.db, "Endpoint.Address"),
                ":",
                GetAtt(self.db, "Endpoint.Port"),
                "/db"
            ])
        ))

    def create_redis(self):
        """ Create an elasticache instance inside the given VPC """
        rediscluster_sg = self.t.add_resource(SecurityGroup(
            '{}RedisClusterSecurityGroup'.format(self.basename),
            VpcId=Ref(self.vpc),
            GroupDescription='redis security group',
            Tags=self.tags,
        ))

        self.ingress(self.eks_node_sg, rediscluster_sg, port=6379,
            description="Allow k8s nodes (and pods) to connect to redis",
            deps=[rediscluster_sg.name, self.eks_node_sg.name])

        redis_node_type = self.t.add_parameter(Parameter(
            "RedisNodeType",
            Default="cache.t2.micro",
            Description="Database instance class",
            Type="String",
            AllowedValues=["cache.t2.micro", "cache.t2.small", "cache.t2.medium",
                           "cache.m3.medium", "cache.m3.large", "cache.m3.xlarge",
                           "cache.m4.large", "cache.m4.xlarge", "cache.m4.2xlarge"],
        ))

        redis_subnet_groups = self.t.add_resource(elasticache.SubnetGroup(
            "{}RedisSubnetGroup".format(self.basename),
            Description="Subnets available for redis instances",
            SubnetIds=[Ref(subnet) for subnet in self.subnets]
        ))

        self.redis = self.t.add_resource(elasticache.CacheCluster(
            '{}RedisCluster'.format(self.basename),
            Engine='redis',
            CacheNodeType=Ref(redis_node_type),
            NumCacheNodes='1',
            VpcSecurityGroupIds=[Ref(rediscluster_sg)],
            CacheSubnetGroupName=Ref(redis_subnet_groups),
            Tags=self.tags,
        ))

        self.t.add_output(Output(
            "RedisBackendUrl",
            Description="Redis (Elasticache) backend url",
            Value=Join("", [
                "redis://",
                GetAtt(self.redis, "RedisEndpoint.Address"),
                ":",
                GetAtt(self.redis, "RedisEndpoint.Port")
            ])
        ))

    def create_elasticsearch(self):
        """ Create an elasticsearch cluster inside the given VPC """
        elasticsearch_sg = self.t.add_resource(SecurityGroup(
            '{}ElasticsearchClusterSecurityGroup'.format(self.basename),
            VpcId=Ref(self.vpc),
            GroupDescription='ElasticSearch security group',
            Tags=self.tags,
        ))
        self.ingress(self.eks_node_sg, elasticsearch_sg, port=443, deps=[elasticsearch_sg.name, self.eks_node_sg.name],
            description="Allow k8s nodes (and pods) to connect to elasticsearch")

        es_node_type = self.t.add_parameter(Parameter(
            "ESNodeType",
            Description="Choose ElasticSearch node instance type",
            Type="String",
            Default="t2.medium.elasticsearch",
            AllowedValues=["t2.small.elasticsearch", "t2.medium.elasticsearch", "m4.large.elasticsearch"],
        ))

        es_node_disk_size = self.t.add_parameter(Parameter(
            "ESNodeDiskSize",
            Description="Choose ElasticSearch node disk size (in GB)",
            Type="Number",
            Default="20",
        ))

        es_node_count = self.t.add_parameter(Parameter(
            "ESNodeCount",
            Description="Number of ElasticSearch nodes in the cluster (must be even if zone-aware)",
            Type="Number",
            Default="4",
        ))

        self.elasticsearch = self.t.add_resource(elasticsearch.Domain(
            '{}ESCluster'.format(self.basename),
            DomainName=Sub(self.basename + '-${AWS::StackName}-' + str(int(time.time()))),
            ElasticsearchClusterConfig=elasticsearch.ElasticsearchClusterConfig(
                DedicatedMasterEnabled=False,      # the master also serves queries and hosts shards
                InstanceCount=Ref(es_node_count),  # node count must be even if zone aware, see:
                ZoneAwarenessEnabled=True,
                # https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-zoneawareness
                InstanceType=Ref(es_node_type),
            ),
            ElasticsearchVersion="6.0",
            EBSOptions=elasticsearch.EBSOptions(EBSEnabled=True,
                                  Iops=0,
                                  VolumeSize=Ref(es_node_disk_size),
                                  VolumeType="gp2"),
            SnapshotOptions=elasticsearch.SnapshotOptions(AutomatedSnapshotStartHour=0),
            AccessPolicies={'Version': '2012-10-17',
                            'Statement': [{
                                'Effect': 'Allow',
                                'Principal': {
                                    'AWS': '*'
                                },
                                'Action': 'es:*',
                                'Resource': '*'
                            }]},
            AdvancedOptions={"rest.action.multi.allow_explicit_index": "true"},
            VPCOptions=elasticsearch.VPCOptions(
                SubnetIds=[Ref(subnet) for subnet in self.subnets[:2]],
                SecurityGroupIds=[Ref(elasticsearch_sg)]
            ),
            Tags=self.tags,
        ))
        self.t.add_output(Output(
            "ElasticsearchUrl",
            Description="Elasticsearch endpoint URL",
            Value=Join("", [
                "https://",
                GetAtt(self.elasticsearch, "DomainEndpoint"),
                ":443/"
            ])
        ))
