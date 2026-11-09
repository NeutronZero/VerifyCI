# verifyci_trusted_harness

## Overview
Trusted Pytest harness plugin package (§15.10 Component D) providing plugin registration and configuration for sandboxed candidate worker execution in VerifyCI.

## Interface
- [`__init__.py:__version__`]: Package version constant (`"3.1.10"`).
- [`pytest_plugin.py:TrustedWorkerPlugin`]: Pytest plugin class explicitly passed to `pytest.main(plugins=[TrustedWorkerPlugin()])` to configure candidate worker invocations.
- [`pytest_plugin.py:TrustedWorkerPlugin.pytest_addoption`]: Hook adding `--candidate-worker-image` and `--candidate-staging` command-line options under the `verifyci-worker` parser group.
- [`pytest_plugin.py:TrustedWorkerPlugin.pytest_configure`]: Hook reading `--candidate-worker-image` and `--candidate-staging` from pytest configuration and binding them to the plugin instance.

## Invariants
- [`pytest_plugin.py:TrustedWorkerPlugin.pytest_addoption`]: Command-line options `--candidate-worker-image` and `--candidate-staging` default to empty strings if unspecified.
- [`pytest_plugin.py:TrustedWorkerPlugin.pytest_configure`]: Candidate worker attributes `worker_image` and `candidate_staging` are populated from the active pytest configuration during test configuration.

## Side Effects
- [`pytest_plugin.py:TrustedWorkerPlugin.pytest_addoption`]: Mutates the pytest CLI argument parser by adding option group `verifyci-worker` and two command-line flags.
- [`pytest_plugin.py:TrustedWorkerPlugin.pytest_configure`]: Mutates plugin instance state by setting `worker_image` and `candidate_staging` attributes.

## Verification
- Run: pytest
