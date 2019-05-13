import base64
import click
import os
import tempfile
import yaml

from .formation import Formation

from .utils import (
    execute,
    get_stack,
    snake_and_caps,
    template_file,
)


@click.group()
def cli():
    pass


@cli.command('formation')
@click.argument('basename')
@click.option('--eks', is_flag=True, default=False, help='Include EKS')
@click.option('--postgres', is_flag=True, default=False, help='Include postgres (RDS)')
@click.option('--redis', is_flag=True, default=False, help='Include redis (ElastiCache)')
@click.option('--elasticsearch', is_flag=True, default=False, help='Include ElasticSearch')
def formation(basename, eks, postgres, redis, elasticsearch):
    formation = Formation(basename=basename, options=dict(eks=eks, postgres=postgres, redis=redis, elasticsearch=elasticsearch))
    if basename == '-':
        print(formation.json())
    else:
        filename = f"{basename}.json"
        with open(filename, 'w') as fp:
            fp.write(formation.json())
        click.echo("Wrote CF JSON to: '{}'".format(filename))
    region = os.environ.get('AWS_REGION', 'eu-west-1')
    click.echo("")
    click.echo(".. Now use the CloudFormation web console to create a stack from this json")
    click.echo(
        "https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks?filter=active".format(
            region=region,
        )
    )


def _add_aws_user_to_kubeconfig(stackname, clustername, kubecfg_file=None):
    if kubecfg_file is None:
        kubecfg_file = '{}/.kube/config'.format(os.environ.get('HOME', ''))
    with open(kubecfg_file) as kubecfg:
        parsed = yaml.load(kubecfg)

    parsed['users'].append({
        'name': stackname,
        'user': {
            'exec': {
                'apiVersion': 'client.authentication.k8s.io/v1alpha1',
                'command': 'aws-iam-authenticator',
                'args': [
                    'token',
                    '-i',
                    clustername,
                ]
            }
        }
    })
    with open(kubecfg_file, 'w') as kubecfg:
        yaml.dump(parsed, kubecfg)


def _check_if_kubeconfig_has_stack_configured(stackname, kubecfg_file=None):
    if kubecfg_file is None:
        kubecfg_file = '{}/.kube/config'.format(os.environ.get('HOME', ''))
    try:
        with open(kubecfg_file) as kubecfg:
            parsed = yaml.load(kubecfg)
    except IOError:
        return False

    (user, cluster, context) = (False, False, False)

    for u in parsed['users']:
        if u['name'] == stackname:
            user = True

    for c in parsed['clusters']:
        if c['name'] == stackname:
            cluster = True

    for ctx in parsed['contexts']:
        if ctx['name'] == stackname:
            context = True

    return all([user, cluster, context])


def setup_datadog(dd_api_key):
    templates = [
        'datadog-rbac.yaml',
        'datadog-agent.yaml',
        'datadog-service.yaml',
    ]
    for template in templates:
        with template_file(template, {'datadog_api_key': dd_api_key}) as tmpf:
            execute("kubectl apply -f {}".format(tmpf))


def setup_traefik(stackname):
    templates = [
        'traefik/rbac.yaml',
        'traefik/svc-depl.yaml',
        'traefik/web-ui.yaml',
    ]
    # 1. Get ACM certificate ARN
    click.echo("Setting traefik up as an ingress controller..")
    click.echo(" - we will setup a default LoadBalancer service pointint to the proxy")
    click.echo(" - it is recommended to use a wildcard *.yourdomain.com SSL certificate with it")
    tpl_vars = {}
    tpl_vars['acm_ssl_arn'] = click.prompt("Please enter the SSL certificate ARN")
    root_domain = tpl_vars['root_domain'] = click.prompt("Please enter the root domain (ie. yourdomain.com)")
    tpl_vars['traefik_root_hostname'] = f"{stackname}-traefik-root.{root_domain}"
    tpl_vars['traefik_webui_hostname'] = f"{stackname}-traefik-webui.{root_domain}"
    for template in templates:
        with template_file(template, tpl_vars) as tmpf:
            execute("kubectl apply -f {}".format(tmpf))


@cli.command('kubeconfig')
@click.argument('stackname')
@click.option('--remove', is_flag=True, default=False, help='instead of adding a stack to kubeconfig, remove it!')
def kubeconfig(stackname, remove):
    stack = get_stack(stackname)

    if stack is None:
        return

    if _check_if_kubeconfig_has_stack_configured(stackname):
        if remove:
            execute("kubectl config delete-context {}".format(stackname))
            execute("kubectl config delete-cluster {}".format(stackname))
            execute("kubectl config unset users.{}".format(stackname))
            return
        else:
            click.echo("-- {} stack (cluster, user, context) found in ~/.kube/config -- not adding!".format(stackname))
            return
    else:
        if remove:
            click.echo("-- {} stack not found in kube config -- not removing!".format(stackname))
            return

    # 1. Add cluster configuration to kubeconfig
    ca_data = base64.b64decode(stack.outputs['EKSClusterCertificateAuthorityData'])
    kube_api_url = stack.outputs['EKSClusterEndpoint']
    eks_arn = stack.outputs['EKSClusterArn']
    clustername = eks_arn.split("/")[-1]
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(ca_data)
        tmpf.flush()
        execute([
            "kubectl",
            "config",
            "set-cluster", stackname,
            "--certificate-authority={}".format(tmpf.name),
            "--server={}".format(kube_api_url),
            "--embed-certs=true",
        ])
    # 2. Add user section to kube config
    _add_aws_user_to_kubeconfig(stackname, clustername)

    # 3. Create kubernetes context
    execute("kubectl config set-context {0} --cluster={0} --user={0}".format(stackname))


@cli.command('finish_setup')
@click.argument('stackname')
def finish_setup(stackname):
    """ Finish stack setup (create/update k8s resources mostly)"""
    stack = get_stack(stackname)

    if stack is None:
        return

    # 1. Check if this stack has been setup in the local kubeconfig
    if not _check_if_kubeconfig_has_stack_configured(stackname):
        click.echo(("-- {0} stack not found in ~/.kube/config!\n"
                    "run spinup kubeconfig {0} before finishing setup").format(stackname))
        return

    # 2. create auth config map so nodes can join cluster, and the users are mapped by their IAM arn's
    instance_role_arn = stack.outputs['eksNodeInstanceRoleArn']
    with template_file('aws-auth-cm.yaml', {'eks_node_instance_role_arn': instance_role_arn}) as tmpf:
        execute("kubectl config use-context {}".format(stackname))
        execute("kubectl apply -f {}".format(tmpf))

    # 3. setup external-dns deployment
    with template_file('external-dns.yaml', {'stackname': stackname}) as tmpf:
        execute("kubectl apply -f {}".format(tmpf))

    # 4. setup kubernetes dashboard (and heapster + influxdb)
    manifests = [
        "https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml",  # noqa
        "https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/influxdb/heapster.yaml",
        "https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/influxdb/influxdb.yaml",
        "https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/rbac/heapster-rbac.yaml",
    ]
    for manifest in manifests:
        execute("kubectl apply -f {}".format(manifest))

    # 5. setup datadog daemonset
    if click.confirm("Do you wish to install datadog to your cluster?"):
        dd_api_key = click.prompt("Enter your datadog api key")
        setup_datadog(dd_api_key)


@cli.command('datadog')
@click.argument('stackname')
@click.argument('api_key')
def datadog(stackname, api_key):
    # 1. Check if this stack has been setup in the local kubeconfig
    if not _check_if_kubeconfig_has_stack_configured(stackname):
        click.echo(("-- {0} stack not found in ~/.kube/config!\n"
                    "run spinup kubeconfig {0} before finishing setup").format(stackname))
        return
    # 2. Use the stack context
    execute("kubectl config use-context {}".format(stackname))
    # 3. Setup the k8s resources for datadog
    setup_datadog(api_key)


@cli.command('traefik')
@click.argument('stackname')
def traefik(stackname):
    # 1. Check if this stack has been setup in the local kubeconfig
    if not _check_if_kubeconfig_has_stack_configured(stackname):
        click.echo(("-- {0} stack not found in ~/.kube/config!\n"
                    "run spinup kubeconfig {0} before finishing setup").format(stackname))
        return
    # 2. Use the stack context
    execute("kubectl config use-context {}".format(stackname))
    # 3. Setup the k8s resources for traefik
    setup_traefik(stackname)


@cli.command('config')
@click.argument('stackname')
def config(stackname):
    """ Dump the stack outputs formatted in config/env style (caps + snake case) """
    stack = get_stack(stackname)
    if stack is None:
        return

    for key, value in stack.outputs.items():
        if key.lower()[:3] != 'eks':   # skip irrelevant EKS outputs (only needed for kubeconfig)
            click.echo("{key}={value}".format(
                key=snake_and_caps(key),
                value=value
            ))


if __name__ == "__main__":
    from ipdb import launch_ipdb_on_exception
    with launch_ipdb_on_exception():
        cli()
