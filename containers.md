---
description: Container security resources for Docker, Kubernetes, image scanning, runtime security, platform hardening, and authorized container testing.
---

# Yellow - Containers

This page covers container and Kubernetes operations, hardening, vulnerability scanning, DFIR, and authorized testing. Keep centralized logging strategy in Security Logging and generic vulnerability management tooling in Blue Defense unless the tool is container-specific.

## Related Sections

Container logging should feed the broader logging strategy.

{% content-ref url="security-logging/" %}
[security-logging](security-logging/)
{% endcontent-ref %}

Container image and dependency scanners also belong with vulnerability management.

{% content-ref url="blue-defense/vulnerability-management.md" %}
[vulnerability-management.md](blue-defense/vulnerability-management.md)
{% endcontent-ref %}

Container labs and vulnerable playgrounds belong in Training.

{% content-ref url="training/practice-lab.md" %}
[practice-lab.md](training/practice-lab.md)
{% endcontent-ref %}

## Container Management

### CLI and Runtime Tools

* [gVisor](https://github.com/google/gvisor) - Container runtime sandbox.
* [ctop](https://github.com/bcicen/ctop) - Top-like interface for container metrics.

### Platforms and Web Tools

* [Moby](https://github.com/moby/moby) - Collaborative open source project for the Docker container ecosystem.
* [Traefik](https://traefik.io/) - Reverse proxy and load balancer with Docker and Let's Encrypt integration.
* [Kong](https://github.com/Kong/kong) - Cloud-native API gateway.
* [Rancher](https://github.com/rancher/rancher) - Kubernetes and container management platform.
* [Portainer](https://github.com/portainer/portainer) - Docker and Kubernetes management UI.

## Logging and Monitoring

Container logging usually combines three layers:

* **Container platform logs:** daemon events, API calls, and container create/modify/delete activity.
* **Host logs:** operating system, kubelet, runtime, and platform logs. For example, Amazon EKS can ship control plane and workload logs to CloudWatch.
* **Application logs:** service logs written to stdout/stderr, a bind mount, or an external collector.

Common collection patterns:

* Persistent volume or bind mount for applications that write to files.
* Application-native logging to an external destination.
* Sidecar or DaemonSet collectors for Kubernetes workloads.
* Runtime log drivers that capture stdout and stderr.

## Container Defense

### Vulnerability and Configuration Scanning

* [Clair](https://github.com/quay/clair) - Static vulnerability analysis for container images.
* [WhaleScan](https://github.com/nccgroup/whalescan) - Windows container vulnerability and benchmark scanner. Verify maintenance before relying on it for current coverage.
* [Trivy](https://github.com/aquasecurity/trivy) - Scanner for container images, filesystems, repositories, and IaC misconfigurations.
* [SecretScanner](https://github.com/deepfence/SecretScanner) - Finds secrets in container images and filesystems.
* [sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) - Tools for analyzing Windows sandbox attack surface.
* [Docker Bench for Security](https://github.com/docker/docker-bench-security) - Checks Docker hosts against common security best practices.
* [Anchore Engine](https://github.com/anchore/anchore-engine) - Legacy Anchore image analysis service. Modern Anchore workflows generally use [Grype](https://github.com/anchore/grype) and [Syft](https://github.com/anchore/syft).
* [GitGuardian Docker security cheat sheet](https://blog.gitguardian.com/how-to-improve-your-docker-containers-security-cheat-sheet/)
* [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

### DFIR and Investigation

* [sysdig-inspect](https://github.com/draios/sysdig-inspect) - Interface for container troubleshooting and security investigation.
  * [sysdig](https://github.com/draios/sysdig)

## Container Pentesting

Use these references only for environments where you have explicit authorization.

### Enumeration and Escapes

* [Pentest Book - Docker and Kubernetes](https://pentestbook.six2dez.com/enumeration/cloud/docker-and-kubernetes)
* [Understanding Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [Escaping containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)
* _PTFM: Container Breakout - pg. 145_

### Offensive Tools

* [kubesploit](https://github.com/cyberark/kubesploit) - Kubernetes-focused post-exploitation C2 framework.
* [deepce](https://github.com/stealthcopter/deepce) - Docker enumeration, privilege escalation, and container escape checks.
* [PENTESTING-BIBLE Docker for Pentesters](https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE/blob/master/8-part-100-article/62_article/Docker%20for%20Pentesters.pdf)
* [PayloadsAllTheThings - Docker Pentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Container%20-%20Docker%20Pentest.md)
* [Docker for Pentesters](https://blog.ropnop.com/docker-for-pentesters/)
* _Operator Handbook: Docker Exploit - pg. 64_

## Docker

[Docker](https://www.docker.com/) packages an application with its runtime, dependencies, system tools, and settings.

### Basics and Reference

* [Docker 101 tutorial](https://www.docker.com/101-tutorial)
* [Docker getting started image](https://hub.docker.com/r/docker/getting-started)
* [Docker Handbook](https://docker-handbook.farhan.dev/)
* [DevOps with Docker](https://devopswithdocker.com/)
* [Docker containers security](https://tbhaxor.com/docker-containers-security/)
* [Docker Jumpstart](http://odewahn.github.io/docker-jumpstart/) - Older but still useful introductory material.
* _Operator Handbook: Docker Commands - pg. 61_

### Misc

* [Whaler](https://github.com/P3GLEG/Whaler) - Reconstructs Dockerfiles from Docker images.

{% file src=".gitbook/assets/Docker-Security-Cheatsheet_hp8lh3.pdf" %}

{% embed url="https://youtu.be/KINjI1tlo2w" %}

## Kubernetes

### Management and Observability

* [Kubernetes](https://kubernetes.io/)
* [kubectl cheat sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
* [red-kube](https://github.com/lightspin-tech/red-kube) - Red-team kubectl cheat sheet.
* _Operator Handbook: KubeCTL - pg. 111_
* [kubebox](https://github.com/astefanutti/kubebox) - Terminal and web console for Kubernetes.
  * [kubebox overview](https://hakin9.org/kubebox-terminal-and-web-console-for-kubernetes/)
* [Kubernetes the Hard Way](https://github.com/kelseyhightower/kubernetes-the-hard-way)
* [Kubernetes the Easy Way](https://github.com/jamesward/kubernetes-the-easy-way)
* [Hubble](https://github.com/cilium/hubble) - Kubernetes network, service, and security observability using eBPF.

### Offensive Tools

* [peirates](https://www.kali.org/tools/peirates/) - Kubernetes penetration tool for authorized privilege escalation and pivot testing.
* [Kubestroyer](https://github.com/Rolix44/Kubestroyer) - Kubernetes misconfiguration exploitation toolkit.

### Security Auditing

* [kubesec](https://github.com/controlplaneio/kubesec) - Kubernetes resource security risk analysis.
* [netassert](https://github.com/controlplaneio/netassert) - Tests Kubernetes NetworkPolicy and related network controls.
* [KubiScan](https://github.com/cyberark/KubiScan) - Scans Kubernetes clusters for risky permissions.
* [rbac-police](https://github.com/PaloAltoNetworks/rbac-police) - Evaluates RBAC permissions with Rego policies.
  * [Kubernetes privilege escalation from excessive permissions](https://www.paloaltonetworks.com/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms)

### Resources

* [Kubernetes basics](https://xapax.github.io/security/#attacking_kubernetes/basics_of_kubernetes/)
* [Kubernetes cheat sheet](https://intellipaat.com/blog/tutorial/devops-tutorial/kubernetes-cheat-sheet/)
* [Kubernetes production best practices](https://learnk8s.io/production-best-practices/)
* _Operator Handbook: Kubernetes - pg. 107_
* [NSA/CISA Kubernetes hardening guidance](https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/1/CTR_KUBERNETES%20HARDENING%20GUIDANCE.PDF)
  * [NCC Group review of the guidance](https://research.nccgroup.com/2021/09/09/nsa-cisa-kubernetes-security-guidance-a-critical-review/)
* [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
* [kubernetes-security-best-practice](https://github.com/freach/kubernetes-security-best-practice)
* [k8s-security](https://github.com/kabachook/k8s-security)
* [Kubernetes pentesting](https://xapax.github.io/security/#attacking_kubernetes/attacking_kubernetes/)
* [Kubernetes pentesting checklist](https://xapax.github.io/security/#attacking_kubernetes/attacking_kubernetes_checklist/)
* _Operator Handbook: Kubernetes Exploit - pg. 108_
* [kubernetes-simulator](https://github.com/kubernetes-simulator/simulator) - Kubernetes security training platform.
* [Kubernetes Goat](https://madhuakula.com/kubernetes-goat/) - Interactive Kubernetes security learning playground.
