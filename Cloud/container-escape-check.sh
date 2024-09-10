#!/bin/bash

# Check if a command exists
CheckCommandExists(){
    command -v "\$1" >/dev/null 2>&1
}

# Install a command if it does not exist
InstallCommand(){
    if ! CheckCommandExists "\$1"; then
        echo -e "\033[93m[!] \$1 command not found. Installing...\033[0m"
        if CheckCommandExists sudo; then
            if CheckCommandExists apt-get; then
                sudo apt-get -y update >/dev/null 2>&1 && sudo apt-get install -y "\$1" >/dev/null 2>&1
            elif CheckCommandExists yum; then
                sudo yum -y update >/dev/null 2>&1 && sudo yum install -y "\$1" >/dev/null 2>&1
            fi
        else
            echo -e "\033[93m[!] Failed to install \$1: sudo command not available.\033[0m"
        fi

        if ! CheckCommandExists "\$1"; then
            echo -e "\033[93m[!] \$1 command installation failed.\033[0m"
        else
            echo -e "\033[93m[!] \$1 command installed successfully.\033[0m"
        fi
    fi
}

# Check if we are in a container environment
CheckContainerEnvironment(){
    local in_container=0
    
    # Method 1: Check cgroup
    if grep -qE '/docker/' /proc/1/cgroup || grep -qE 'docker' /proc/self/cgroup; then
        in_container=1
    fi

    # Method 2: Check hostname
    if [ "$(hostname | grep -c 'docker')" -gt 0 ]; then
        in_container=1
    fi

    # Method 3: Check for /.dockerenv file
    if [ -f /.dockerenv ]; then
        in_container=1
    fi

    # Method 4: Check /proc/self/cgroup
    if grep -qE "container=([^/]+/)?docker" /proc/self/cgroup; then
        in_container=1
    fi

    # Method 5: Check Kubernetes environment variables
    if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
        in_container=1
    fi

    # Output result based on the check
    if [ $in_container -eq 0 ]; then
        echo -e "\033[31m[-] Not currently a container environment.\033[0m"
        exit 1
    fi
    echo -e "\033[33m[!] Currently in a container, checking ......\033[0m"
    VulnerabilityExists=0
}

# Generic privilege and mount checks
CheckCondition(){
    local description="\$1"
    local condition="\$2"
    if eval "$condition"; then
        echo -e "\033[92m[+] $description.\033[0m"
        VulnerabilityExists=1
    fi
}

# Check if the kernel version falls within the vulnerability range
CheckKernelVersion(){
    local min_version="\$1"
    local max_version="\$2"
    local kernel_version
    kernel_version=$(uname -r | awk -F '-' '{print \$1}')

    if [[ "$kernel_version" > "$min_version" && "$kernel_version" < "$max_version" ]]; then
        return 0
    else
        return 1
    fi
}

# Collection of CVE check functions
CheckCVE(){
    local cve_description="\$1"
    local min_version="\$2"
    local max_version="\$3"

    if CheckKernelVersion "$min_version" "$max_version"; then
        echo -e "\033[92m[+] $cve_description vulnerability exists.\033[0m"
        VulnerabilityExists=1
    fi
}

# Run all checks
RunChecks(){
    CheckContainerEnvironment

    # Check privileged mode
    CheckCondition "The current container is in privileged mode" '[ "$(grep -qi "0000003fffffffff" /proc/self/status)" ]'

    # Check Docker socket mount
    CheckCondition "Docker socket is mounted" '[ -f "/var/run/docker.sock" ]'

    # Check Procfs mount
    CheckCondition "Procfs is mounted" '[ "$(find / -name core_pattern 2>/dev/null | wc -l)" -gt 1 ]'

    # Check root directory mount
    CheckCondition "Root directory is mounted" '[ "$(find / -name passwd 2>/dev/null | grep /etc/passwd | wc -l)" -gt 6 ]'

    # Check Docker Remote API
    InstallCommand hostname
    local IP
    IP=$(hostname -i | awk -F. '{print \$1 "." \$2 "." \$3 ".1"}')
    for PORT in "2375" "2376"; do
        CheckCondition "Docker Remote API is enabled" "[ \"$(timeout 3 bash -c 'echo >/dev/tcp/$IP/$PORT' >/dev/null 2>&1; echo $?)\" -eq 0 ]"
    done

    # Check specific CVEs
    CheckCVE "CVE-2016-5195 DirtyCow" "2.6.22" "4.8.3"
    CheckCVE "CVE-2020-14386" "4.6" "5.9"
    CheckCVE "CVE-2022-0847 DirtyPipe" "5.8" "5.10.102"

    InstallCommand capsh
    # Check CAP_DAC_READ_SEARCH and CAP_SYS_ADMIN privileges
    CheckCondition "CAP_DAC_READ_SEARCH is present" 'capsh --print | grep -q cap_dac_read_search'
    CheckCondition "CAP_SYS_ADMIN is present" 'capsh --print | grep -q cap_sys_admin'
    CheckCondition "CAP_SYS_PTRACE is present" 'capsh --print | grep -q cap_sys_ptrace'

    if [ $VulnerabilityExists -eq 0 ]; then
        echo -e "\033[33m[!] No vulnerabilities found.\033[0m"
    else
        echo -e "\033[33m[!] Vulnerabilities found.\033[0m"
    fi
}

RunChecks

