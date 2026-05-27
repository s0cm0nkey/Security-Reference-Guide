# Install Scripts

Use this page for install notes that are useful when setting up command-line tooling. Avoid copying old package-install snippets blindly: Linux package names, repositories, and dependencies change quickly.

## PowerShell on Linux

The old PowerShell 6.0.2 Ubuntu 16.04 install snippet that used `libssl1.0.0` and `libicu55` is now obsolete. Use Microsoft's current installation documentation instead.

* [Install PowerShell on Linux](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux)
* [PowerShell GitHub Releases](https://github.com/PowerShell/PowerShell/releases)

## PenTesters Framework

The PenTesters Framework (PTF) is offensive tooling and is better treated as part of the Red Offensive toolbox. If you still use it in a lab, install from the current repository rather than old copied snippets.

```bash
sudo git clone https://github.com/trustedsec/ptf /opt/ptf
cd /opt/ptf
sudo ./ptf
```

{% content-ref url="../../red-offensive/offensive-toolbox/" %}
[offensive-toolbox](../../red-offensive/offensive-toolbox/)
{% endcontent-ref %}
