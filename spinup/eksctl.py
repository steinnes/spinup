import os

KEYPAIR = os.getenv("KEYPAIR")

def generate_eksctl_yaml(stack, region):
    config = {"apiVersion": "eksctl.io/v1alpha5", "kind": "ClusterConfig"}

    outputs = _output_dict_zip(stack["Outputs"])
    basename = outputs["basename"]

    config["metadata"] = {"name": basename, "region": region}

    eks_node_security_group = outputs["eksNodeSecurityGroup"]
    config["vpc"] = _subnet_config(basename, outputs)

    config["nodeGroups"] = _node_group_config(basename, eks_node_security_group)

    return config


def _node_group_config(basename, node_sg):
    node_group = {
        "name": f"{basename}-nodes",
        "instanceType": "m5.large",
        "desiredCapacity": 4,
        "privateNetworking": True,
        "maxSize": 5,
        "minSize": 3,
        "ssh": {"publicKeyName": KEYPAIR, "allow": True},
        "securityGroups": {"withShared": True, "withLocal": True, "attachIDs": [node_sg]}

    }
    return [node_group]


def _subnet_config(basename, outputs):
    subnets = {"private": {}}
    for i in range(int(outputs["NumberOfSubnets"])):
        subnet = f"{basename}Subnet{i}"
        subnet_az = outputs[f"{subnet}AvailabilityZone"]
        subnets["private"][subnet_az] = {"id": outputs[subnet]}
    return {"subnets": subnets}


def _output_dict_zip(output_list):
    outputs = {}
    for output in output_list:
        outputs[output["OutputKey"]] = output["OutputValue"]
    return outputs
