# spinup

## DEPRECATION WARNING

This tool is not being actively developed and is available here for
educational purposes.  If you want a nice way to get up and running
with EKS, I suggest you check out [eksctl](https://github.com/weaveworks/eksctl).

---

Quickly get up and running with an EKS cluster in a brand new VPC.  Because
doing that by hand is extremely tedious.

To try and support more workflows it can output the CloudFormation JSON, which
can then be used from the AWS console to either create stacks or changesets.

## Commands

## Usage

```

$ spinup
Usage: spinup [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  config        Dump the stack outputs formatted in...
  datadog
  finish_setup  Finish stack setup (create/update k8s...
  formation
  kubeconfig
  traefik

```

### Creating a new formation

The first step in using spinup is to create a new cloud formation json file:

    $ spinup formation [--options..] formation.json
    Wrote CF JSON to: 'formation.json'

    .. Now use the CloudFormation web console to create a stack from this json
    https://eu-west-1.console.aws.amazon.com/cloudformation/home?region=eu-west-1#/stacks?filter=active


After creating a new stack in the AWS console, you need to configure your local
kubectl configuration, which can be done with `spinup` thanks to the stack exposing
the EKS URL and secrets.

    $ spinup kubeconfig mybrandnewstack

Here `mybrandnewstack` is the stack name given in the AWS web console when creating
the stack.

If everything went well, spinup will not output any information.  Next run `finish_setup`:

    $ spinup finish_setup mybrandnewstack

And finally you can use `spinup` to install k8s services like `datadog` and `traefik`.
