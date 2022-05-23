# Containers

## Container Management

### **CLI Tools**

* [**gvisor**](https://github.com/google/gvisor) - container runtime sandbox.
* [**ctop**](https://github.com/bcicen/ctop) - top-like interface for container metrics.

### **Web Tools**

* &#x20;[**Moby**](https://github.com/moby/moby) - a collaborative project for the container ecosystem to assemble container-based system.
* [**Traefik**](https://traefik.io/) - open source reverse proxy/load balancer provides easier integration with Docker and Let's encrypt.
* [**kong**](https://github.com/Kong/kong) - The Cloud-Native API Gateway.
* [**rancher**](https://github.com/rancher/rancher) - complete container management platform.

## Logging and Monitoring

Container logging and analysis revolves around 3 areas:

* Container Service Logs - Service daemons record key events
  * Daemon events - Errors, status, and general events
  * Remote calls to APIs
  * Creation/Modification/Deletion of containers
* Host operating system/platform logs
  * Amazon EKS offers logging events to Cloudwatch
* Service logs

### Logging Methods

* Persistent data volume or bind mount - Log data is sent to a persistent location outside of the container. Often with syslog directly to the host OS
* Application inside container - If the application itself has logging capabilities, they can be logged to locations outside of the container
* Monitoring container (Sidecar) - A container for collecting logs from other containers
* Daemon log drivers - Captures stdout and stderr of containers

## Container Defense

### Tools

* Security Auditing and Vulnerability Scanners
  * [Clair](https://github.com/quay/clair) - Vulnerability Static Analysis for Containers
  * [WhaleScan](https://github.com/nccgroup/whalescan) - Whalescan is a vulnerability scanner for Windows containers, which performs several benchmark checks, as well as checking for CVEs/vulnerable packages on the container
  * [Trivy](https://github.com/aquasecurity/trivy) - Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues
  * [SecretScanner](https://github.com/deepfence/SecretScanner) - Find secrets and passwords in container images and file systems
  * [sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) - Set of tools to analyze Windows sandboxes for exposed attack surface.
* DFIR
  * [sysdig-inspect](https://github.com/draios/sysdig-inspect) - A powerful opensource interface for container troubleshooting and security investigation
    * [https://github.com/draios/sysdig](https://github.com/draios/sysdig)
* Container Management
  * [rancher](https://github.com/rancher/rancher) - Complete container management platform
  * [portainer](https://github.com/portainer/portainer) - Making Docker and Kubernetes management easy.

## Container Pen Testing

* Enumeration
  * [https://pentestbook.six2dez.com/enumeration/cloud/docker-and-and-kubernetes](https://pentestbook.six2dez.com/enumeration/cloud/docker-and-and-kubernetes)
* Container Escapes
  * [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
  * [https://pwning.systems/posts/escaping-containers-for-fun/](https://pwning.systems/posts/escaping-containers-for-fun/)
  * Container Breakout - _PTFM: Container Breakout - pg. 145_
* Tools
  * [kubesploit](https://github.com/cyberark/kubesploit) - Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments.

## Docker

[Docker](https://www.docker.com/) - A Docker container is a lightweight, standalone, executable package of software that includes everything needed to run an application: code, runtime, system tools, system libraries and settings.

* Basic and Reference
  * [https://www.docker.com/101-tutorial](https://www.docker.com/101-tutorial)
  * [https://hub.docker.com/r/docker/getting-started](https://hub.docker.com/r/docker/getting-started)
  * [https://docker-handbook.farhan.dev/](https://docker-handbook.farhan.dev/)
  * [https://devopswithdocker.com/](https://devopswithdocker.com/)
  * [https://tbhaxor.com/docker-containers-security/](https://tbhaxor.com/docker-containers-security/)
  * [Docker Jumpstart](http://odewahn.github.io/docker-jumpstart/) - Andrew Odewahn
* _Operator Handbook: Docker Commands - pg. 61_
* Offensive Testing
  * [deepce](https://github.com/stealthcopter/deepce) - Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
  * [PENTESTING-BIBLE/DockerforPentesters](https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE/blob/master/8-part-100-article/62\_article/Docker%20for%20Pentesters.pdf)
  * [PayloadsAllTheThings/DockerPentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Container%20-%20Docker%20Pentest.md)
  * [https://blog.ropnop.com/docker-for-pentesters/](https://blog.ropnop.com/docker-for-pentesters/)
  * _Operator Handbook: Docker Exploit- pg. 64_
* Defense and Hardening
  * [docker-bench-security](https://github.com/docker/docker-bench-security) - The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production.
  * [Anchore](https://github.com/anchore/anchore-engine) - A service that analyzes docker images and applies user-defined acceptance policies to allow automated container image validation and certification
  * [https://blog.gitguardian.com/how-to-improve-your-docker-containers-security-cheat-sheet/](https://blog.gitguardian.com/how-to-improve-your-docker-containers-security-cheat-sheet/)
  * [https://cheatsheetseries.owasp.org/cheatsheets/Docker\_Security\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Docker\_Security\_Cheat\_Sheet.html)
* Misc
  * [Whaler](https://github.com/P3GLEG/Whaler) - Program to reverse Docker images into Docker files

{% file src="../.gitbook/assets/Docker-Security-Cheatsheet_hp8lh3.pdf" %}

{% embed url="https://youtu.be/KINjI1tlo2w" %}

## [Kubernetes](https://kubernetes.io/)

### Tools

* Container Management
  * KubeCTL Kubernetes command line tool
    * [https://kubernetes.io/docs/reference/kubectl/cheatsheet/](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
    * [GitHub - lightspin-tech/red-kube: Red Team KubeCTL Cheat Sheet](https://github.com/lightspin-tech/red-kube)&#x20;
    * _Operator Handbook: KubeCTL- pg. 111_
  * [kubebox](https://github.com/astefanutti/kubebox) - Terminal and Web console for Kubernetes
    * [https://hakin9.org/kubebox-terminal-and-web-console-for-kubernetes/](https://hakin9.org/kubebox-terminal-and-web-console-for-kubernetes/)
  * [**kubernetes-the-hard-way**](https://github.com/kelseyhightower/kubernetes-the-hard-way) - bootstrap Kubernetes the hard way on Google Cloud Platform. No scripts.
  * [**kubernetes-the-easy-way**](https://github.com/jamesward/kubernetes-the-easy-way) - bootstrap Kubernetes the easy way on Google Cloud Platform. No scripts.
  * [Hubble](https://github.com/cilium/hubble) is a Network, Service & Security Observability for Kubernetes using eBPF.
* Offensive tools
  * [peirates](https://www.kali.org/tools/peirates/)  - a Kubernetes penetration tool, enables an attacker to escalate privilege and pivot through a Kubernetes cluster. It automates known techniques to steal and collect service accounts, obtain further code execution, and gain control of the cluster.
* Security auditing
  * [kubesec](https://github.com/controlplaneio/kubesec) - Security risk analysis for Kubernetes resources
  * [netassert](https://github.com/controlplaneio/netassert) - This is a security testing framework for fast, safe iteration on firewall, routing, and NACL rules for Kubernetes ([Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/), services) and non-containerised hosts (cloud provider instances, VMs, bare metal).

### Resources

* Basics and Reference
  * [https://xapax.github.io/security/#attacking\_kubernetes/basics\_of\_kubernetes/](https://xapax.github.io/security/#attacking\_kubernetes/basics\_of\_kubernetes/)
  * [https://intellipaat.com/blog/tutorial/devops-tutorial/kubernetes-cheat-sheet/](https://intellipaat.com/blog/tutorial/devops-tutorial/kubernetes-cheat-sheet/)
  * [kubernetes-production-best-practices](https://learnk8s.io/production-best-practices/) - checklists with best-practices for production-ready Kubernetes.
  * _Operator Handbook: Kubernetes - pg. 107_
* Security Auditing and Hardening
  * [NSA Kubernetes hardening guide](https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/1/CTR\_KUBERNETES%20HARDENING%20GUIDANCE.PDF)
  * [https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes\_Security\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes\_Security\_Cheat\_Sheet.html)
  * [kubernetes-security-best-practice](https://github.com/freach/kubernetes-security-best-practice)
  * [k8s-security](https://github.com/kabachook/k8s-security) - kubernetes security notes and best practices.
* Pen Testing
  * [https://xapax.github.io/security/#attacking\_kubernetes/attacking\_kubernetes/](https://xapax.github.io/security/#attacking\_kubernetes/attacking\_kubernetes/)
  * [https://xapax.github.io/security/#attacking\_kubernetes/attacking\_kubernetes\_checklist/](https://xapax.github.io/security/#attacking\_kubernetes/attacking\_kubernetes\_checklist/)
  * _Operator Handbook: Kubernetes Exploit - pg. 108_
* Training
  * [kubernetes-simulator](https://github.com/kubernetes-simulator/simulator) - Kubernetes Security Training Platform - Focusing on security mitigation
  * [https://madhuakula.com/kubernetes-goat/](https://madhuakula.com/kubernetes-goat/) - Interactive Kubernetes Security Learning Playground
