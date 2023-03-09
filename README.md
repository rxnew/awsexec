# awsexec

[![release](https://github.com/rxnew/awsexec/actions/workflows/release.yml/badge.svg)](https://github.com/rxnew/awsexec/actions/workflows/release.yml)

A simple CLI tool that sets AWS credentials into environment variables based on profiles.
No dependence on external software, such as Gnome Keyring, makes it work in any environment.

## Installation

### Linux and Mac

```shell
curl -L https://github.com/rxnew/awsexec/releases/latest/download/awsexec-$(uname -s)-$(uname -m).tar.gz | tar -zx
```

## Quick Start

```shell
awsexec your-aws-profile -- env
```
